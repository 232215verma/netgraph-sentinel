"""
NetGraph Sentinel — Phase 4/7: Live Pipeline + Demo Sequences

Every NEW alert is broadcast over the WebSocket together with the graph
shape it describes:

    {"event": "alert", "alert": {..., "graph": {"nodes": [...], "links": [...]}}}

so the dashboard can draw a real star (port scan) / hub (DDoS) / fan-out
(DGA) instead of a single line. The alert saved to the database is the
original one, without the "graph" field.

PHASE 1 changes (marked "PHASE 1"):
  - the broadcast alert now carries its database id (save_alert returns it),
    so the dashboard's 30 s poll no longer re-adds alerts it already has
  - flows from IPs blocked by the (simulated) external firewall are dropped
"""

import asyncio
from datetime import datetime, timedelta

import pandas as pd

import replayer  # PHASE 1: simulated external firewall state (BLOCKED_IPS)
from flow_parser import load_and_normalize, normalize_flows
from detector import detect_flows
from database import save_alert
from graph_engine import build_graph, get_graph_anomalies, alert_to_graph_elements
from traffic_generator import (
    ATTACK_GENERATORS,
    generate_benign_traffic,
    COLUMNS,
)

RUN_DETECTOR_EVERY_N_BATCHES = 3

DEMO_NARRATION = {
    "portscan": "🚪 Port Scan — one host is probing many hosts and ports, looking for an open door.",
    "dga": "🎲 DGA Domains — malware is generating random domain names to find its control server.",
    "dnstunnel": "🕳️ DNS Tunneling — data is being smuggled out disguised as oversized DNS lookups.",
    "c2": "📡 C2 Beaconing — an infected host is checking in with its controller on a fixed schedule.",
    "ddos": "🌊 DDoS — a flood of traffic from hundreds of sources is overwhelming one target.",
    "exfil": "📤 Data Exfiltration — a quiet host suddenly moves a large amount of data out.",
}


def _alert_key(alert: dict) -> tuple:
    return (alert["type"], alert.get("source"), alert.get("target"))


# PHASE 1 -------------------------------------------------------------------
def _drop_blocked(batch: pd.DataFrame) -> pd.DataFrame:
    """Flows from IPs the external firewall has blocked never reach the sensor."""
    if replayer.BLOCKED_IPS:
        return batch[~batch["src_ip"].isin(replayer.BLOCKED_IPS)]
    return batch
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Graph shape for an alert
# ---------------------------------------------------------------------------
def _graph_for_alert(alert: dict, graph_alerts: list[dict]) -> dict:
    """
    Find the graph-engine alert(s) describing the same threat (same type,
    same source or same target) and merge their nodes/links. A port scan
    that is found both as "many ports on one host" and "many hosts" ends
    up as ONE combined star. If nothing matches, fall back to a plain
    source -> target edge.
    """
    t = alert["type"]
    nodes: dict[str, dict] = {}
    links: dict[tuple, dict] = {}

    for ga in graph_alerts:
        if ga["type"] != t:
            continue
        same_src = bool(alert.get("source")) and ga.get("source") == alert.get("source")
        same_tgt = bool(alert.get("target")) and ga.get("target") == alert.get("target")
        if not (same_src or same_tgt):
            continue
        n, l = alert_to_graph_elements(ga)
        for node in n:
            nodes.setdefault(node["id"], node)
        for link in l:
            links.setdefault((link["source"], link["target"]), link)

    if not links:  # fallback: plain edge
        src, dst = alert.get("source"), alert.get("target")
        for node_id in (src, dst):
            if node_id:
                nodes.setdefault(
                    node_id,
                    {"id": node_id, "flagged": True, "types": [t], "primaryType": t},
                )
        if src and dst:
            links[(src, dst)] = {"source": src, "target": dst, "type": t}

    return {"nodes": list(nodes.values()), "links": list(links.values())}


async def _emit_new_alerts(alerts: list[dict], accumulated: pd.DataFrame,
                           seen_alert_keys: set, ws_manager) -> None:
    """Save + broadcast every alert we have not sent before."""
    new_alerts = []
    for alert in alerts:
        key = _alert_key(alert)
        if key in seen_alert_keys:
            continue
        seen_alert_keys.add(key)
        new_alerts.append(alert)

    if not new_alerts:
        return

    # one graph build per detection run, shared by all new alerts
    try:
        graph_alerts = get_graph_anomalies(build_graph(accumulated))
    except Exception:
        graph_alerts = []

    for alert in new_alerts:
        alert_id = save_alert(alert)  # PHASE 1: original alert saved unchanged; returns its DB id
        enriched = {**alert, "id": alert_id, "graph": _graph_for_alert(alert, graph_alerts)}
        await ws_manager.broadcast({"event": "alert", "alert": enriched})


# ---------------------------------------------------------------------------
# Full CSV simulation
# ---------------------------------------------------------------------------
async def run_simulation(csv_path: str, ws_manager, batch_size: int = 20, delay_seconds: float = 0.5):
    flows = load_and_normalize(csv_path)
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    flows = flows.assign(_ts=flows["timestamp"]).sort_values("_ts", na_position="last").drop(columns="_ts")

    accumulated = pd.DataFrame(columns=flows.columns)
    seen_alert_keys = set()
    total = len(flows)
    batch_num = 0

    await ws_manager.broadcast({"event": "simulation_started", "total_flows": total})

    for start in range(0, total, batch_size):
        batch = _drop_blocked(flows.iloc[start:start + batch_size])  # PHASE 1
        accumulated = pd.concat([accumulated, batch], ignore_index=True)
        batch_num += 1

        await ws_manager.broadcast({
            "event": "batch_processed",
            "batch": batch_num,
            "flows_so_far": len(accumulated),
        })

        is_last = start + batch_size >= total
        if batch_num % RUN_DETECTOR_EVERY_N_BATCHES == 0 or is_last:
            alerts = detect_flows(accumulated)
            await _emit_new_alerts(alerts, accumulated, seen_alert_keys, ws_manager)

        if delay_seconds > 0 and not is_last:
            await asyncio.sleep(delay_seconds)

    await ws_manager.broadcast({"event": "simulation_complete", "total_alerts": len(seen_alert_keys)})


# ---------------------------------------------------------------------------
# Presenter-controlled demos
# ---------------------------------------------------------------------------
def _build_single_attack_flows(attack_key: str, benign_count: int = 100) -> pd.DataFrame:
    """Build benign + ONE attack, already normalized, ready for the detector."""
    start = datetime(2026, 3, 1, 9, 0, 0)
    rows = generate_benign_traffic(benign_count, start)
    rows.extend(ATTACK_GENERATORS[attack_key](start + timedelta(minutes=2)))

    raw = pd.DataFrame(rows, columns=COLUMNS)
    flows = normalize_flows(raw)
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    return flows.sort_values("timestamp", na_position="last")


async def run_single_attack_demo(attack_key: str, ws_manager, delay_seconds: float = 0.3, batch_size: int = 15):
    """Replay ONE attack type on demand — for live, presenter-controlled demos."""
    flows = _build_single_attack_flows(attack_key)
    accumulated = pd.DataFrame(columns=flows.columns)
    seen_alert_keys = set()
    total = len(flows)
    batch_num = 0

    await ws_manager.broadcast({
        "event": "stage_announcement",
        "text": DEMO_NARRATION.get(attack_key, attack_key),
    })
    await ws_manager.broadcast({"event": "simulation_started", "total_flows": total})

    for start in range(0, total, batch_size):
        batch = _drop_blocked(flows.iloc[start:start + batch_size])  # PHASE 1
        accumulated = pd.concat([accumulated, batch], ignore_index=True)
        batch_num += 1

        await ws_manager.broadcast({
            "event": "batch_processed",
            "batch": batch_num,
            "flows_so_far": len(accumulated),
        })

        is_last = start + batch_size >= total
        if is_last or batch_num % 2 == 0:
            alerts = detect_flows(accumulated)
            await _emit_new_alerts(alerts, accumulated, seen_alert_keys, ws_manager)

        if delay_seconds > 0 and not is_last:
            await asyncio.sleep(delay_seconds)

    await ws_manager.broadcast({"event": "simulation_complete", "total_alerts": len(seen_alert_keys)})


async def run_full_demo_sequence(ws_manager):
    """
    Scripted demo: walks through all 6 threats in a suggested order,
    saving a strong finale for last (per the design doc's advice to
    save the most impressive attack for last).
    """
    order = ["portscan", "dga", "dnstunnel", "c2", "exfil", "ddos"]  # DDoS finale — big visual payoff
    for attack_key in order:
        await run_single_attack_demo(attack_key, ws_manager, delay_seconds=0.25, batch_size=15)
        await asyncio.sleep(1.5)  # pause between stages so the presenter can narrate

    await ws_manager.broadcast({
        "event": "stage_announcement",
        "text": "✅ Demo complete — all 6 threat types detected across graph, rules, ML, and anomaly layers.",
    })