"""
NetGraph Sentinel — Phase 1: Attack Arena

Lets the analyst launch an attack (or the full kill chain) from the
dashboard. Each stage:

    benign background + attack flows  ->  (temp CSV so flow_parser is used
    unchanged)  ->  detect_flows()  ->  keep ONLY alerts of the launched
    attack type for the chosen attacker  ->  save_alert() (ledger,
    campaign, node state)  ->  WebSocket push

Every WebSocket message carries "origin": "arena". While an Arena attack is
running the dashboard ignores messages WITHOUT this tag (live monitoring),
so the topology graph shows only the attack the analyst launched.

Same protocol as pipeline.py otherwise:  stage_announcement ->
simulation_started -> batch_processed -> alert (with "graph" and "id") ->
simulation_complete.

Safe by design: everything is synthetic and stays inside this process.
No packet is ever sent to the IP addresses typed into the console.
"""

import asyncio
import logging
import os
import tempfile
from datetime import datetime, timedelta

import pandas as pd

import replayer
from database import save_alert
from detector import detect_flows
from flow_parser import load_and_normalize
from graph_engine import build_graph, get_graph_anomalies
from pipeline import _graph_for_alert
from traffic_generator import (
    COLUMNS,
    EXTERNAL_C2_IP,
    KILL_CHAIN,
    generate_attack_flows,
    generate_benign_traffic,
)

log = logging.getLogger("netgraph.arena")

BENIGN_BACKGROUND_FLOWS = 150  # the detectors need normal traffic to compare against

ARENA_NARRATION = {
    "PortScan": "Attack Arena: {attacker} is scanning {dst} and its neighbours, looking for open ports and hosts.",
    "C2Beaconing": "Attack Arena: {attacker} is checking in with its command server {dst} on a fixed schedule.",
    "Exfiltration": "Attack Arena: {attacker} is sending a large volume of data out to {dst}.",
    "DDoS": "Attack Arena: a flood of sources is overwhelming {dst}.",
    "DGA": "Attack Arena: {attacker} is generating random domain names to find its control server.",
    "DNSTunneling": "Attack Arena: {attacker} is smuggling data out inside oversized DNS lookups to {dst}.",
}

_TASKS: set[asyncio.Task] = set()  # keep references so tasks are not garbage-collected


def _log_task_result(task: asyncio.Task) -> None:
    _TASKS.discard(task)
    if not task.cancelled() and task.exception() is not None:
        log.error("arena task failed", exc_info=task.exception())


def spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _TASKS.add(task)
    task.add_done_callback(_log_task_result)


async def _send(manager, message: dict) -> None:
    """Every Arena message is tagged so the dashboard can tell it from live monitoring."""
    await manager.broadcast({**message, "origin": "arena"})


# ---------------------------------------------------------------------------
# One stage: generate -> detect -> save  (blocking, run in a worker thread)
# ---------------------------------------------------------------------------
def _detect_and_save(kind: str, attacker_ip: str, dst_ip: str) -> tuple[int, list[dict]]:
    """Returns (number of flows analysed, alerts ready to broadcast)."""
    start = datetime.now()
    rows = generate_benign_traffic(BENIGN_BACKGROUND_FLOWS, start)
    rows += generate_attack_flows(kind, attacker_ip, dst_ip, start + timedelta(seconds=2))
    df = pd.DataFrame(rows, columns=COLUMNS)

    # go through flow_parser exactly like real CSV data does
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        df.to_csv(path, index=False)
        flows = load_and_normalize(path)
    finally:
        os.remove(path)
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )

    alerts = detect_flows(flows)

    # Keep ONLY the launched attack type for the chosen attacker. Other types
    # (e.g. a generic "Anomaly") would replace the attack's shape on the graph.
    if kind == "DDoS":
        mine = [a for a in alerts if a["type"] == "DDoS" and a.get("target") == dst_ip]
    else:
        mine = [a for a in alerts if a["type"] == kind and a.get("source") == attacker_ip]

    # graph shapes (star / hub / fan-out) so the dashboard draws the real pattern
    try:
        graph_alerts = get_graph_anomalies(build_graph(flows))
    except Exception:
        graph_alerts = []

    out = []
    for a in mine:
        alert_id = save_alert(a)  # ledger + campaign + node state happen inside
        out.append({**a, "id": alert_id, "graph": _graph_for_alert(a, graph_alerts)})
    return len(flows), out


async def run_stage(kind: str, attacker_ip: str, dst_ip: str, manager, prefix: str = "") -> int:
    """Run one attack stage. Returns the number of alerts produced (0 if blocked)."""
    if kind != "DDoS" and replayer.is_blocked(attacker_ip):
        await _send(manager, {
            "event": "stage_announcement",
            "text": f"{prefix}{attacker_ip} is blocked by the external firewall, so its traffic no longer reaches the sensor.",
        })
        log.info("stage %s skipped: %s is blocked", kind, attacker_ip)
        return 0

    await _send(manager, {
        "event": "stage_announcement",
        "text": prefix + ARENA_NARRATION[kind].format(attacker=attacker_ip, dst=dst_ip),
    })

    total_flows, alerts = await asyncio.to_thread(_detect_and_save, kind, attacker_ip, dst_ip)

    await _send(manager, {"event": "simulation_started", "total_flows": total_flows})
    await _send(manager, {"event": "batch_processed", "batch": 1, "flows_so_far": total_flows})
    for a in alerts:
        await _send(manager, {"event": "alert", "alert": a})
    await _send(manager, {"event": "simulation_complete", "total_alerts": len(alerts)})

    log.info("stage %s from %s -> %d alerts", kind, attacker_ip, len(alerts))
    return len(alerts)


# ---------------------------------------------------------------------------
# Public entry points (called from main.py)
# ---------------------------------------------------------------------------
async def run_single_attack(kind: str, attacker_ip: str, target_ip: str, manager) -> None:
    await run_stage(kind, attacker_ip, target_ip, manager)


async def run_kill_chain(attacker_ip: str, target_ip: str, manager) -> None:
    """Recon -> C2 -> Exfiltration, spaced out so the graph visibly changes state."""
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    total = len(KILL_CHAIN)
    for i, (delay, kind, where) in enumerate(KILL_CHAIN, start=1):
        await asyncio.sleep(max(0.0, delay - (loop.time() - t0)))
        if replayer.is_blocked(attacker_ip):
            await _send(manager, {
                "event": "stage_announcement",
                "text": f"Kill chain halted at stage {i}/{total}: {attacker_ip} was isolated by the analyst.",
            })
            return
        dst = target_ip if where == "target" else EXTERNAL_C2_IP
        await run_stage(kind, attacker_ip, dst, manager, prefix=f"Kill chain {i}/{total} · ")