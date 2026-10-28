"""
NetGraph Sentinel — Phase 2: Graph Engine (the core / USP)

Turns flow data into a live network graph (NetworkX DiGraph) — IPs become
nodes, connections become edges — and looks at how the SHAPE of that graph
changes to spot attacks, on top of (and independent from) any single-flow
check.

Every threat has its OWN drawable shape (see alert_to_graph_elements):

    PortScan      -> STAR      one scanner, spokes to many hosts and ports
    DDoS          -> FUNNEL    many sources converging on one target
    DGA           -> COMB      one bot fanning out to many one-off destinations
    C2Beaconing   -> RING      bot -> check-ins -> C2 -> replies -> bot (a loop)
    DNSTunneling  -> PIPELINE  source -> oversized queries in a row -> resolver
    Exfiltration  -> DIAMOND   source -> burst of outbound transfers -> destination

The nodes of a ring / pipeline / diamond between the two real hosts stand
for the repeated flows that were observed (check-ins, queries, bursts).
They are a drawing aid, not extra hosts. The dashboard pins every node to a
fixed position per shape (frontend/src/shapeLayout.ts).

PHASE 1 addition: node attack-state machine (next_node_state), see the
block just above the standalone test.
"""

from __future__ import annotations

import re
import statistics

import networkx as nx
import pandas as pd


# ---------------------------------------------------------------------------
# Building the graph
# ---------------------------------------------------------------------------
def build_graph(flows: pd.DataFrame) -> nx.DiGraph:
    """
    Build a directed graph from normalized flow data (the schema
    flow_parser.py produces). One edge per (src_ip, dst_ip) pair; repeated
    flows between the same pair accumulate onto the same edge instead of
    creating duplicates, so the edge holds the FULL history of that pair.
    """
    G = nx.DiGraph()

    for _, row in flows.iterrows():
        src, dst = row["src_ip"], row["dst_ip"]
        if pd.isna(src) or pd.isna(dst):
            continue

        if not G.has_edge(src, dst):
            G.add_edge(
                src, dst,
                ports=set(),
                flow_count=0,
                total_bytes=0,
                timestamps=[],
            )

        edge = G[src][dst]
        if pd.notna(row.get("dst_port")):
            edge["ports"].add(int(row["dst_port"]))
        edge["flow_count"] += 1
        if pd.notna(row.get("total_bytes")):
            edge["total_bytes"] += row["total_bytes"]
        if pd.notna(row.get("timestamp")):
            edge["timestamps"].append(row["timestamp"])

    return G


# ---------------------------------------------------------------------------
# Snapshot metrics — the numbers behind the shapes
# ---------------------------------------------------------------------------
def node_metrics(G: nx.DiGraph) -> dict[str, dict]:
    """Per-node degree and byte-volume metrics for the current graph snapshot."""
    metrics = {}
    for node in G.nodes:
        out_edges = G.out_edges(node, data=True)
        in_edges = G.in_edges(node, data=True)

        metrics[node] = {
            "out_degree": G.out_degree(node),
            "in_degree": G.in_degree(node),
            "bytes_out": sum(d["total_bytes"] for _, _, d in out_edges),
            "bytes_in": sum(d["total_bytes"] for _, _, d in in_edges),
        }
    return metrics


# ---------------------------------------------------------------------------
# Anomaly detection — graph shape -> alert
# ---------------------------------------------------------------------------
def detect_port_scans(
    G: nx.DiGraph,
    port_threshold: int = 15,
    host_threshold: int = 8,
    max_targets_in_alert: int = 30,
) -> list[dict]:
    """
    Port-scan shapes (both are a "star" around the scanner):

      (a) vertical   - one src -> one dst touching MANY distinct ports
      (b) horizontal - one src -> MANY dsts, each with only a few tiny,
                       non-DNS flows (a host sweep)

    Alerts carry the ports / targets so the frontend can draw a real star.
    """
    alerts = []

    # (a) many ports on one host
    for src, dst, data in G.edges(data=True):
        num_ports = len(data["ports"])
        if num_ports >= port_threshold:
            ports = sorted(int(p) for p in data["ports"])
            alerts.append({
                "type": "PortScan",
                "source": src,
                "target": dst,
                "ports": ports[:max_targets_in_alert],
                "evidence": f"{src} touched {num_ports} distinct ports on {dst}",
                "confidence": min(0.99, 0.5 + num_ports / 100),
            })

    # (b) one source sweeping many hosts with tiny, few-flow probes
    for node in G.nodes:
        targets = []
        for _, dst, d in G.out_edges(node, data=True):
            avg_bytes = d["total_bytes"] / max(d["flow_count"], 1)
            if d["flow_count"] <= 3 and avg_bytes < 500 and 53 not in d["ports"]:
                targets.append(dst)
        if len(targets) >= host_threshold:
            alerts.append({
                "type": "PortScan",
                "source": node,
                "targets": targets[:max_targets_in_alert],
                "evidence": f"{node} probed {len(targets)} distinct hosts with tiny flows",
                "confidence": min(0.99, 0.5 + len(targets) / 60),
            })
    return alerts


def detect_ddos(
    G: nx.DiGraph,
    indegree_threshold: int = 15,
    max_sources_in_alert: int = 40,
) -> list[dict]:
    """
    Hub shape: one node receiving edges from many distinct source nodes.
    The alert lists the sources so the frontend can draw the hub.
    """
    alerts = []
    for node in G.nodes:
        indeg = G.in_degree(node)
        if indeg >= indegree_threshold:
            alerts.append({
                "type": "DDoS",
                "target": node,
                "sources": list(G.predecessors(node))[:max_sources_in_alert],
                "evidence": f"{node} received connections from {indeg} distinct sources",
                "confidence": min(0.99, 0.5 + indeg / 300),
            })
    return alerts


def detect_dga(G: nx.DiGraph, outdegree_threshold: int = 12, max_flows_per_edge: int = 2) -> list[dict]:
    """
    Fan-out shape: one node contacting many distinct destinations over DNS
    (port 53), each only once or twice. Real DGA malware never talks to the
    same (fake, algorithm-generated) domain/IP twice.
    """
    alerts = []
    for node in G.nodes:
        one_off = [
            dst for _, dst, d in G.out_edges(node, data=True)
            if d["flow_count"] <= max_flows_per_edge and 53 in d["ports"]
        ]
        if len(one_off) >= outdegree_threshold:
            alerts.append({
                "type": "DGA",
                "source": node,
                "targets": one_off[:30],
                "evidence": f"{node} contacted {len(one_off)} distinct DNS destinations, each only 1-2 times",
                "confidence": min(0.95, 0.4 + len(one_off) / 80),
            })
    return alerts


def detect_c2_beaconing(G: nx.DiGraph, min_beacons: int = 5, regularity_threshold: float = 0.25) -> list[dict]:
    """
    Regular-timing shape: the same edge (src -> dst) repeating at
    suspiciously EVEN time intervals. Regularity is measured as
    coefficient of variation (stdev / mean) of the gaps between
    consecutive timestamps — low = very regular = beacon-like.
    """
    alerts = []
    for src, dst, data in G.edges(data=True):
        ts_list = sorted(t for t in data["timestamps"] if pd.notna(t))
        if len(ts_list) < min_beacons:
            continue

        gaps = [
            (ts_list[i + 1] - ts_list[i]).total_seconds()
            for i in range(len(ts_list) - 1)
            if isinstance(ts_list[i], pd.Timestamp)
        ]
        if len(gaps) < min_beacons - 1 or statistics.mean(gaps) == 0:
            continue

        coeff_of_variation = statistics.pstdev(gaps) / statistics.mean(gaps)
        if coeff_of_variation <= regularity_threshold:
            alerts.append({
                "type": "C2Beaconing",
                "source": src,
                "target": dst,
                "count": len(ts_list),  # how many check-ins were seen (used to draw the ring)
                "evidence": (
                    f"{src} contacted {dst} {len(ts_list)} times at "
                    f"~{statistics.mean(gaps):.1f}s intervals (very regular)"
                ),
                "confidence": min(0.95, 0.6 + (regularity_threshold - coeff_of_variation)),
            })
    return alerts


def detect_exfiltration(G: nx.DiGraph, zscore_threshold: float = 2.0, min_bytes: int = 100_000) -> list[dict]:
    """
    Outlier-volume shape: one node's outbound byte total is a big
    statistical outlier compared to every other node — a normally-quiet
    node suddenly moving a lot of data. Requires BOTH a high z-score AND
    a meaningful absolute byte volume, so small early-batch noise
    doesn't trigger false alarms.
    """
    metrics = node_metrics(G)
    bytes_out_values = [m["bytes_out"] for m in metrics.values() if m["bytes_out"] > 0]
    if len(bytes_out_values) < 3:
        return []

    mean = statistics.mean(bytes_out_values)
    stdev = statistics.pstdev(bytes_out_values) or 1  # avoid divide-by-zero

    alerts = []
    for node, m in metrics.items():
        if m["bytes_out"] < min_bytes:
            continue
        z = (m["bytes_out"] - mean) / stdev
        if z >= zscore_threshold:
            # the biggest outbound destination, so the alert has a link to draw
            top_dst = max(
                G.out_edges(node, data=True),
                key=lambda e: e[2]["total_bytes"],
                default=None,
            )
            alert = {
                "type": "Exfiltration",
                "source": node,
                "evidence": f"{node} sent {m['bytes_out']:,} bytes out — {z:.1f} std devs above average",
                "confidence": min(0.95, 0.5 + z / 10),
            }
            if top_dst is not None:
                alert["target"] = top_dst[1]
                alert["count"] = top_dst[2]["flow_count"]  # how many transfers (used to draw the diamond)
            alerts.append(alert)
    return alerts


def detect_dns_tunneling(G: nx.DiGraph, min_avg_bytes: int = 500, min_flows: int = 5) -> list[dict]:
    """
    Oversized-DNS shape: repeated traffic on port 53 (DNS) whose average
    payload size per flow is way bigger than a normal DNS lookup
    (normal DNS is usually well under 200 bytes per flow).
    """
    alerts = []
    for src, dst, data in G.edges(data=True):
        if 53 not in data["ports"]:
            continue
        if data["flow_count"] < min_flows:
            continue
        avg_bytes = data["total_bytes"] / data["flow_count"]
        if avg_bytes >= min_avg_bytes:
            alerts.append({
                "type": "DNSTunneling",
                "source": src,
                "target": dst,
                "count": data["flow_count"],  # how many oversized queries (used to draw the pipeline)
                "evidence": (
                    f"{src} sent {data['flow_count']} DNS flows to {dst} averaging "
                    f"{avg_bytes:.0f} bytes each (normal DNS is much smaller)"
                ),
                "confidence": min(0.95, 0.5 + avg_bytes / 4000),
            })
    return alerts


def get_graph_anomalies(G: nx.DiGraph) -> list[dict]:
    """Run every detector and return one combined, sorted alert list."""
    alerts = []
    alerts += detect_port_scans(G)
    alerts += detect_ddos(G)
    alerts += detect_dga(G)
    alerts += detect_c2_beaconing(G)
    alerts += detect_exfiltration(G)
    alerts += detect_dns_tunneling(G)
    alerts.sort(key=lambda a: a["confidence"], reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# Alert -> drawable graph elements (for the dashboard)
# ---------------------------------------------------------------------------
def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _count_of(alert: dict, pattern: str, default: int) -> int:
    """How many flows an alert is about: the 'count' field, else parsed from the evidence text."""
    c = alert.get("count")
    if isinstance(c, (int, float)) and c > 0:
        return int(c)
    ev = alert.get("evidence")
    text = " ".join(ev) if isinstance(ev, list) else str(ev or "")
    m = re.search(pattern, text)
    return int(m.group(1)) if m else default


def alert_to_graph_elements(alert: dict) -> tuple[list[dict], list[dict]]:
    """
    Expand ONE graph alert into (nodes, links) the frontend can draw.
    Each threat type gets its own shape:

      PortScan     STAR      scanner -> every probed host / host:port
      DDoS         FUNNEL    every source -> target
      DGA          COMB      bot -> every contacted destination
      C2Beaconing  RING      src -> check-in 1..k -> dst -> reply 1..k -> src
      DNSTunneling PIPELINE  src -> query 1..k -> resolver
      Exfiltration DIAMOND   src -> burst 1..k -> destination

    Nodes are de-duplicated by id and match the frontend's GraphNode shape
    {id, flagged, types, primaryType} plus optional drawing hints:
      key   - an important endpoint: drawn bigger and always labelled
      minor - a spoke or pulse node: drawn small
      label - text to show instead of the id
    Links match GraphLink {source, target, type}. Every link endpoint is
    guaranteed to exist in the returned nodes list (react-force-graph needs that).
    """
    t = alert["type"]
    nodes: dict[str, dict] = {}
    links: list[dict] = []

    def add_node(node_id: str, **extra):
        if node_id and node_id not in nodes:
            nodes[node_id] = {"id": node_id, "flagged": True, "types": [t], "primaryType": t, **extra}

    def add_link(src: str, dst: str):
        if src and dst:
            add_node(src)
            add_node(dst)
            links.append({"source": src, "target": dst, "type": t})

    src, dst = alert.get("source"), alert.get("target")

    if t == "PortScan":  # STAR
        add_node(src, key=True)
        for host in alert.get("targets", []):
            add_node(host, minor=True)
            add_link(src, host)
        if alert.get("ports"):
            add_node(dst, key=True)
            add_link(src, dst)
            for p in alert["ports"]:
                pid = f"{dst}:{p}"
                add_node(pid, minor=True, label=f":{p}")
                add_link(src, pid)

    elif t == "DDoS":  # FUNNEL
        add_node(dst, key=True)
        for s in alert.get("sources", []):
            add_node(s, minor=True)
            add_link(s, dst)

    elif t == "DGA":  # COMB
        add_node(src, key=True)
        for d in alert.get("targets", []):
            add_node(d, minor=True)
            add_link(src, d)

    elif t == "C2Beaconing" and src and dst:  # RING: src -> check-ins -> dst -> replies -> src
        k = _clamp(_count_of(alert, r"(\d+)\s+times", 4), 3, 6)
        base = f"{src}>{dst}"
        add_node(src, key=True)
        add_node(dst, key=True)
        prev = src
        for i in range(1, k + 1):
            nid = f"{base}~req{i}"
            add_node(nid, minor=True, label=f"check-in {i}")
            add_link(prev, nid)
            prev = nid
        add_link(prev, dst)
        prev = dst
        for i in range(1, k + 1):
            nid = f"{base}~ack{i}"
            add_node(nid, minor=True, label=f"reply {i}")
            add_link(prev, nid)
            prev = nid
        add_link(prev, src)

    elif t == "DNSTunneling" and src and dst:  # PIPELINE: src -> query 1..k -> resolver
        k = _clamp(_count_of(alert, r"sent\s+(\d+)\s+DNS", 4), 3, 6)
        base = f"{src}>{dst}"
        add_node(src, key=True)
        prev = src
        for i in range(1, k + 1):
            nid = f"{base}~dns{i}"
            add_node(nid, minor=True, label=f"query {i}")
            add_link(prev, nid)
            prev = nid
        add_node(dst, key=True)
        add_link(prev, dst)

    elif t == "Exfiltration" and src and dst:  # DIAMOND: src -> burst 1..k -> destination
        k = _clamp(_count_of(alert, r"(\d+)\s+(?:flows|transfers)", 5), 3, 7)
        base = f"{src}>{dst}"
        add_node(src, key=True)
        add_node(dst, key=True)
        for i in range(1, k + 1):
            nid = f"{base}~burst{i}"
            add_node(nid, minor=True, label=f"burst {i}")
            add_link(src, nid)
            add_link(nid, dst)

    else:  # anything else (or an alert without both ends): plain source -> target edge
        add_link(src, dst)
        if src:
            add_node(src)
        if dst:
            add_node(dst)

    return list(nodes.values()), links


# ===========================================================================
# PHASE 1: node attack-state machine (pure logic, persistence lives in
# database.py / campaigns.py)
#
#   normal -> suspicious -> compromised -> quarantined
#
#   suspicious   : any alert with confidence >= 0.70
#   compromised  : 2+ distinct MITRE tactics from the same host, OR one
#                  severe tactic (C2 / Exfiltration / Impact) at >= 0.80
#   quarantined  : set ONLY by an analyst response (never automatically)
# ===========================================================================
NODE_STATE_RANK = {"normal": 0, "suspicious": 1, "compromised": 2, "quarantined": 3}
SEVERE_TACTICS = {"Command and Control", "Exfiltration", "Impact"}
SUSPICIOUS_CONF = 0.70
COMPROMISED_CONF = 0.80


def next_node_state(
    current: str,
    confidence: float,
    tactics_seen: set[str],
    latest_tactic: str | None = None,
) -> str:
    """Return the new state for a host after one more alert. Never downgrades."""
    if current == "quarantined":
        return current  # the analyst's decision is final

    new = current if current in NODE_STATE_RANK else "normal"

    if confidence >= SUSPICIOUS_CONF and NODE_STATE_RANK[new] < NODE_STATE_RANK["suspicious"]:
        new = "suspicious"

    escalate = len(tactics_seen) >= 2 or (
        latest_tactic in SEVERE_TACTICS and confidence >= COMPROMISED_CONF
    )
    if escalate:
        new = "compromised"

    return new


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    from flow_parser import load_and_normalize

    if len(sys.argv) < 2:
        print("Usage: python graph_engine.py <path-to-csv>")
        print("Example: python graph_engine.py ../data/synthetic_traffic.csv")
        sys.exit(1)

    flows = load_and_normalize(sys.argv[1])
    # Parse timestamps to real datetimes so beaconing regularity math works
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )

    print(f"Building graph from {len(flows)} flows...")
    G = build_graph(flows)
    print(f"Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.\n")

    anomalies = get_graph_anomalies(G)
    if not anomalies:
        print("No anomalies detected.")
    else:
        print(f"Detected {len(anomalies)} anomalies:\n")
        for a in anomalies:
            nodes, links = alert_to_graph_elements(a)
            print(
                f"[{a['type']}] confidence={a['confidence']:.2f} — {a['evidence']}"
                f"  (draws {len(nodes)} nodes, {len(links)} links)"
            )