"""
NetGraph Sentinel — Phase 1: Replayer

Streams normalized flow data in small time-ordered batches, simulating a
live one-way traffic feed (since we don't have a real data diode to tap).

PHASE 1 addition: a registry of IPs blocked by the (simulated) out-of-band
firewall. VYUH itself never blocks anything; this only models what the
EXTERNAL firewall does after an analyst orders a block, i.e. new flows
from that IP stop arriving.
"""

import time
from pathlib import Path
from typing import Iterator

import pandas as pd

from flow_parser import load_and_normalize

# ===========================================================================
# PHASE 1: simulated external firewall state
# ===========================================================================
BLOCKED_IPS: set[str] = set()


def block_ip(ip: str) -> None:
    BLOCKED_IPS.add(ip)


def unblock_ip(ip: str) -> None:
    BLOCKED_IPS.discard(ip)


def clear_blocked() -> None:
    BLOCKED_IPS.clear()


def is_blocked(ip: str) -> bool:
    return ip in BLOCKED_IPS
# ===========================================================================


def replay_flows(
    csv_path: str | Path,
    batch_size: int = 50,
    delay_seconds: float = 1.0,
    max_flows: int | None = None,
) -> Iterator[pd.DataFrame]:
    flows = load_and_normalize(csv_path)

    parsed_ts = pd.to_datetime(flows["timestamp"], errors="coerce")
    flows = flows.assign(_ts=parsed_ts).sort_values("_ts", na_position="last")
    flows = flows.drop(columns="_ts")

    if max_flows is not None:
        flows = flows.head(max_flows)

    total = len(flows)
    for start in range(0, total, batch_size):
        batch = flows.iloc[start : start + batch_size]

        # PHASE 1: drop flows from IPs the external firewall has blocked
        if BLOCKED_IPS:
            batch = batch[~batch["src_ip"].isin(BLOCKED_IPS)]
            if batch.empty:
                if delay_seconds > 0 and start + batch_size < total:
                    time.sleep(delay_seconds)
                continue

        yield batch
        if delay_seconds > 0 and start + batch_size < total:
            time.sleep(delay_seconds)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python replayer.py <path-to-csv> [max_flows]")
        sys.exit(1)

    csv_file = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else 200

    print(f"Replaying {csv_file} (capped at {cap} flows)...\n")
    batch_num = 0
    for batch in replay_flows(csv_file, batch_size=20, delay_seconds=0.5, max_flows=cap):
        batch_num += 1
        print(f"--- Batch {batch_num}: {len(batch)} flows ---")
        print(batch[["src_ip", "dst_ip", "dst_port", "label"]].to_string(index=False))
        print()

    print(f"Done. Replayed {batch_num} batches.")