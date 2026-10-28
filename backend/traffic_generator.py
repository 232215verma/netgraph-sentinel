"""
NetGraph Sentinel — Phase 1: Synthetic Traffic Generator

Generates our own labeled flow data instead of downloading CICIDS2017.
Output uses the exact same column names as CICIDS2017 CSVs (Source IP,
Destination IP, etc.) so flow_parser.py and replayer.py work on it with
ZERO changes.

Produces a mix of:
  - benign traffic (normal-looking connections)
  - one or more of the 6 threats: portscan, ddos, c2, dga, dnstunnel, exfil

Graph shapes the attacks are built to produce:
  - portscan -> STAR  (one scanner -> many hosts, plus many ports on one host)
  - ddos     -> HUB   (many sources -> one target)
  - dga      -> fan-out (one bot -> many one-off DNS destinations)

Usage:
    python traffic_generator.py                      # benign + all 6 attacks
    python traffic_generator.py --attack portscan     # benign + just portscan
    python traffic_generator.py --out ../data/my.csv  # custom output path

PHASE 1 addition: generate_attack_flows() + KILL_CHAIN for the Attack Arena
(see the block just above build_dataset).
"""

import argparse
import ipaddress
import random
from datetime import datetime, timedelta

import pandas as pd

COLUMNS = [
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Label",
]

COMMON_PORTS = [80, 443, 22, 53, 3389, 25, 110, 143]


def _random_internal_ip() -> str:
    return f"192.168.1.{random.randint(2, 250)}"


def _random_external_ip() -> str:
    return str(ipaddress.IPv4Address(random.randint(0x08000000, 0xDFFFFFFF)))


def _distinct_internal_ips(n: int, exclude: set | None = None) -> list[str]:
    """n different internal IPs, none of them in `exclude`."""
    exclude = set(exclude or [])
    pool = [f"192.168.1.{i}" for i in range(2, 251) if f"192.168.1.{i}" not in exclude]
    return random.sample(pool, n)


def _fmt(ts: datetime) -> str:
    return ts.strftime("%d/%m/%Y %H:%M:%S")


# ---------------------------------------------------------------------------
# Benign traffic — everyday-looking connections, varied IPs/ports/sizes
# ---------------------------------------------------------------------------
def generate_benign_traffic(n: int, start_time: datetime) -> list[dict]:
    rows = []
    t = start_time
    for _ in range(n):
        t += timedelta(seconds=random.uniform(0.5, 5))
        port = random.choice(COMMON_PORTS)

        # Real DNS traffic is tiny (~40-100 bytes) — keep it realistic so
        # it doesn't accidentally get flagged as DNS tunneling.
        if port == 53:
            fwd_bytes = random.randint(40, 90)
            bwd_bytes = random.randint(40, 90)
        else:
            fwd_bytes = random.randint(500, 5000)
            bwd_bytes = random.randint(500, 8000)

        rows.append({
            "Source IP": _random_internal_ip(),
            "Destination IP": _random_external_ip(),
            "Source Port": random.randint(40000, 65000),
            "Destination Port": port,
            "Protocol": 6,
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(50000, 500000),
            "Total Fwd Packets": random.randint(3, 30),
            "Total Backward Packets": random.randint(3, 30),
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": bwd_bytes,
            "Label": "BENIGN",
        })
    return rows


# ---------------------------------------------------------------------------
# 1. Port Scanning — a STAR: one attacker sweeps MANY hosts (a few ports
#    each) AND hammers one main target across MANY ports, all very fast
# ---------------------------------------------------------------------------
def generate_port_scan(start_time: datetime, attacker_ip: str = None,
                        target_ip: str = None, num_ports: int = 60,
                        num_hosts: int = 12, ports_per_host: int = 3) -> list[dict]:
    attacker_ip = attacker_ip or _random_internal_ip()
    if target_ip is None:
        target_ip = _distinct_internal_ips(1, exclude={attacker_ip})[0]

    # extra hosts for the horizontal sweep (star arms)
    sweep_hosts = _distinct_internal_ips(num_hosts, exclude={attacker_ip, target_ip})

    probes = [(target_ip, p) for p in random.sample(range(1, 10000), num_ports)]
    for host in sweep_hosts:
        for p in random.sample([21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 8080], ports_per_host):
            probes.append((host, p))
    random.shuffle(probes)

    rows = []
    t = start_time
    for dst_ip, port in probes:
        t += timedelta(milliseconds=random.uniform(10, 80))  # very fast
        rows.append({
            "Source IP": attacker_ip,
            "Destination IP": dst_ip,
            "Source Port": random.randint(40000, 65000),
            "Destination Port": port,
            "Protocol": 6,
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(100, 2000),
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 60,
            "Total Length of Bwd Packets": 0,
            "Label": "PortScan",
        })
    return rows


# ---------------------------------------------------------------------------
# 2. DDoS — a HUB: MANY source IPs flood ONE target, in a short time window
# ---------------------------------------------------------------------------
def generate_ddos(start_time: datetime, target_ip: str = None,
                   num_attackers: int = 200) -> list[dict]:
    target_ip = target_ip or _random_internal_ip()

    # guarantee every attacker IP is DIFFERENT, so the hub really has
    # `num_attackers` spokes instead of a few accidental duplicates
    sources = set()
    while len(sources) < num_attackers:
        sources.add(_random_external_ip())

    rows = []
    t = start_time
    for src_ip in sources:
        t += timedelta(milliseconds=random.uniform(1, 20))  # flood — very tight timing
        rows.append({
            "Source IP": src_ip,
            "Destination IP": target_ip,
            "Source Port": random.randint(1024, 65000),
            "Destination Port": 80,
            "Protocol": 6,
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(10, 200),
            "Total Fwd Packets": random.randint(1, 3),
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": random.randint(40, 200),
            "Total Length of Bwd Packets": 0,
            "Label": "DDoS",
        })
    return rows


# ---------------------------------------------------------------------------
# 3. C2 Beaconing — ONE infected host "checks in" with ONE controller IP on
#    a fixed schedule, every time with nearly identical (small) size
# ---------------------------------------------------------------------------
def generate_c2_beaconing(start_time: datetime, bot_ip: str = None,
                           c2_ip: str = None, num_beacons: int = 30,
                           interval_seconds: int = 60) -> list[dict]:
    bot_ip = bot_ip or _random_internal_ip()
    c2_ip = c2_ip or _random_external_ip()
    rows = []
    t = start_time
    for _ in range(num_beacons):
        t += timedelta(seconds=interval_seconds + random.uniform(-1, 1))  # regular!
        rows.append({
            "Source IP": bot_ip,
            "Destination IP": c2_ip,
            "Source Port": random.randint(40000, 65000),
            "Destination Port": 443,
            "Protocol": 6,
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(200, 500),
            "Total Fwd Packets": 2,
            "Total Backward Packets": 2,
            "Total Length of Fwd Packets": random.randint(150, 170),  # nearly constant
            "Total Length of Bwd Packets": random.randint(150, 170),
            "Label": "C2Beaconing",
        })
    return rows


# ---------------------------------------------------------------------------
# 4. DGA Domains — ONE infected host contacts MANY different IPs (standing
#    in for many random algorithm-generated domain names), one-off each
# ---------------------------------------------------------------------------
def generate_dga_domains(start_time: datetime, bot_ip: str = None,
                          num_domains: int = 40) -> list[dict]:
    bot_ip = bot_ip or _random_internal_ip()

    destinations = set()
    while len(destinations) < num_domains:
        destinations.add(_random_external_ip())

    rows = []
    t = start_time
    for dst_ip in destinations:
        t += timedelta(seconds=random.uniform(2, 10))
        rows.append({
            "Source IP": bot_ip,
            "Destination IP": dst_ip,  # stands in for a DGA domain's IP
            "Source Port": random.randint(40000, 65000),
            "Destination Port": 53,
            "Protocol": 17,  # UDP, typical for DNS
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(50, 300),
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Total Length of Fwd Packets": random.randint(40, 80),
            "Total Length of Bwd Packets": random.randint(40, 80),
            "Label": "DGA",
        })
    return rows


# ---------------------------------------------------------------------------
# 5. DNS Tunneling — DNS queries (port 53) with UNUSUALLY LARGE payloads
#    (real DNS lookups are tiny; tunneling hides data in oversized queries)
# ---------------------------------------------------------------------------
def generate_dns_tunneling(start_time: datetime, source_ip: str = None,
                            dns_server_ip: str = None, num_queries: int = 25) -> list[dict]:
    source_ip = source_ip or _random_internal_ip()
    dns_server_ip = dns_server_ip or _random_external_ip()
    rows = []
    t = start_time
    for _ in range(num_queries):
        t += timedelta(seconds=random.uniform(1, 4))
        rows.append({
            "Source IP": source_ip,
            "Destination IP": dns_server_ip,
            "Source Port": random.randint(40000, 65000),
            "Destination Port": 53,
            "Protocol": 17,
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(100, 400),
            "Total Fwd Packets": random.randint(2, 5),
            "Total Backward Packets": random.randint(2, 5),
            # abnormally large for DNS — normal DNS is ~40-90 bytes
            "Total Length of Fwd Packets": random.randint(800, 2000),
            "Total Length of Bwd Packets": random.randint(800, 2000),
            "Label": "DNSTunneling",
        })
    return rows


# ---------------------------------------------------------------------------
# 6. Data Exfiltration — a normally-quiet internal IP suddenly sends a LOT
#    of data to one external IP in a short burst
# ---------------------------------------------------------------------------
def generate_data_exfiltration(start_time: datetime, source_ip: str = None,
                                dest_ip: str = None, num_flows: int = 15) -> list[dict]:
    source_ip = source_ip or _random_internal_ip()
    dest_ip = dest_ip or _random_external_ip()
    rows = []
    t = start_time
    for _ in range(num_flows):
        t += timedelta(seconds=random.uniform(0.5, 2))
        rows.append({
            "Source IP": source_ip,
            "Destination IP": dest_ip,
            "Source Port": random.randint(40000, 65000),
            "Destination Port": 443,
            "Protocol": 6,
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(5000, 20000),
            "Total Fwd Packets": random.randint(500, 2000),
            "Total Backward Packets": random.randint(5, 20),
            # huge outbound volume, tiny inbound — classic exfil shape
            "Total Length of Fwd Packets": random.randint(500000, 2000000),
            "Total Length of Bwd Packets": random.randint(100, 1000),
            "Label": "Exfiltration",
        })
    return rows


ATTACK_GENERATORS = {
    "portscan": generate_port_scan,
    "ddos": generate_ddos,
    "c2": generate_c2_beaconing,
    "dga": generate_dga_domains,
    "dnstunnel": generate_dns_tunneling,
    "exfil": generate_data_exfiltration,
}


# ===========================================================================
# PHASE 1: Attack Arena support
# ===========================================================================
# Names the dashboard sends  ->  keys of ATTACK_GENERATORS
ARENA_KINDS = {
    "PortScan": "portscan",
    "DDoS": "ddos",
    "C2Beaconing": "c2",
    "DGA": "dga",
    "DNSTunneling": "dnstunnel",
    "Exfiltration": "exfil",
}

# Documentation-range IP (RFC 5737) used as the external C2 / drop server
EXTERNAL_C2_IP = "203.0.113.10"

# Kill chain: (delay in seconds from start, attack kind, destination)
#   "target"   -> the victim IP chosen in the dashboard
#   "external" -> EXTERNAL_C2_IP (C2 server and exfil drop point are outside)
KILL_CHAIN = [
    (0, "PortScan", "target"),
    (8, "C2Beaconing", "external"),
    (20, "Exfiltration", "external"),
]


def generate_attack_flows(kind: str, attacker_ip: str, dst_ip: str,
                          start_time: datetime) -> list[dict]:
    """
    Run ONE attack generator with the attacker/destination the analyst
    chose. `kind` is a dashboard name (e.g. "PortScan").

    DDoS has no single attacker (the shape is MANY sources -> one target),
    so for it only dst_ip is used.
    """
    key = ARENA_KINDS[kind]
    if key == "portscan":
        return generate_port_scan(start_time, attacker_ip=attacker_ip, target_ip=dst_ip)
    if key == "ddos":
        return generate_ddos(start_time, target_ip=dst_ip)
    if key == "c2":
        # 12 beacons, 10 s apart: regular enough to trip the beaconing detector quickly
        return generate_c2_beaconing(start_time, bot_ip=attacker_ip, c2_ip=dst_ip,
                                     num_beacons=12, interval_seconds=10)
    if key == "dga":
        return generate_dga_domains(start_time, bot_ip=attacker_ip)
    if key == "dnstunnel":
        return generate_dns_tunneling(start_time, source_ip=attacker_ip, dns_server_ip=dst_ip)
    return generate_data_exfiltration(start_time, source_ip=attacker_ip, dest_ip=dst_ip)
# ===========================================================================


def build_dataset(attacks: list[str], benign_count: int = 300) -> pd.DataFrame:
    """Build benign traffic plus the requested attack(s), all interleaved
    in a single time window, then return as a DataFrame sorted by time."""
    start = datetime(2026, 1, 15, 9, 0, 0)
    all_rows = generate_benign_traffic(benign_count, start)

    for name in attacks:
        # Stagger each attack's start time a bit into the benign window
        attack_start = start + timedelta(minutes=random.randint(2, 15))
        all_rows.extend(ATTACK_GENERATORS[name](attack_start))

    df = pd.DataFrame(all_rows, columns=COLUMNS)
    df["_ts"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S")
    df = df.sort_values("_ts").drop(columns="_ts")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic NetGraph Sentinel test traffic.")
    parser.add_argument(
        "--attack", nargs="*", default=list(ATTACK_GENERATORS.keys()),
        choices=list(ATTACK_GENERATORS.keys()),
        help="Which attack type(s) to inject. Default: all 6.",
    )
    parser.add_argument(
        "--benign", type=int, default=300,
        help="How many benign flows to generate. Default: 300.",
    )
    parser.add_argument(
        "--out", default="../data/synthetic_traffic.csv",
        help="Output CSV path. Default: ../data/synthetic_traffic.csv",
    )
    args = parser.parse_args()

    dataset = build_dataset(args.attack, args.benign)
    dataset.to_csv(args.out, index=False)

    print(f"Wrote {len(dataset)} flows to {args.out}")
    print(f"Label counts:\n{dataset['Label'].value_counts()}")