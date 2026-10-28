"""
NetGraph Sentinel — Phase 1: Campaign builder, node states and analyst response

Called from database.save_alert() for EVERY saved alert, so campaigns and
node states stay in sync no matter where the alert came from (simulation,
scripted demo, Attack Arena).

  on_alert_saved()  alert -> campaign stage (MITRE tactic) + node state
  isolate_node()    analyst response: quarantine + simulated out-of-band block

VYUH itself stays read-only. isolate_node() never touches the detection
path; it records the analyst's decision and tells the *simulated external
firewall* (replayer.BLOCKED_IPS) to stop that host's traffic.
"""

import logging
import threading
from datetime import datetime, timezone

import database as db
import replayer
from detector import campaign_severity, tactic_for
from graph_engine import next_node_state

log = logging.getLogger("netgraph.response")
_LOCK = threading.RLock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def on_alert_saved(alert: dict, alert_id: int) -> None:
    """
    Update the attacker's campaign and node state from one saved alert.

    Only alerts with a `source` are tracked: a DDoS hub has MANY sources,
    so it is a per-victim event, not a single-attacker campaign.
    """
    src = alert.get("source")
    if not src:
        return

    conf = float(alert.get("confidence", 0.0))
    tactic = tactic_for(alert["type"])  # None for generic "Anomaly"
    when = alert.get("created_at") or _now()

    with _LOCK:
        camp = db.get_campaign(src)

        if tactic:
            tactic_name, tactic_id = tactic
            if camp is None:
                camp = {
                    "id": f"camp-{src}",
                    "src_ip": src,
                    "stages": [],
                    "severity": "low",
                    "status": "active",
                    "first_seen": when,
                    "last_seen": when,
                }
            stage = next((s for s in camp["stages"] if s["tactic"] == tactic_name), None)
            if stage:
                stage["confidence"] = max(stage["confidence"], conf)
            else:
                camp["stages"].append({
                    "tactic": tactic_name,
                    "tactic_id": tactic_id,
                    "threat_class": alert["type"],
                    "first_ts": when,
                    "confidence": conf,
                })
            camp["last_seen"] = when
            camp["severity"] = campaign_severity(camp["stages"])
            db.save_campaign(camp)

        tactics_seen = {s["tactic"] for s in camp["stages"]} if camp else set()
        current = db.get_node_state(src) or "normal"
        new_state = next_node_state(current, conf, tactics_seen, tactic[0] if tactic else None)
        if new_state != current:
            db.set_node_state(src, new_state)
            log.info("node %s: %s -> %s", src, current, new_state)


def firewall_webhook(ip: str, analyst: str) -> dict:
    """
    MOCK out-of-band response channel (stands in for a firewall / NAC API
    that sits OUTSIDE the monitoring enclave). Replace the body with a real
    HTTP call if you ever connect one.
    """
    log.warning("OUT-OF-BAND BLOCK requested for %s by %s (simulated)", ip, analyst)
    return {
        "ip": ip,
        "analyst": analyst,
        "channel": "out-of-band (simulated)",
        "at": _now(),
    }


def isolate_node(ip: str, analyst: str = "analyst") -> dict:
    """Analyst decision: quarantine the node and ask the external firewall to block it."""
    with _LOCK:
        db.set_node_state(ip, "quarantined")
        camp = db.get_campaign(ip)
        if camp:
            camp["status"] = "contained"
            db.save_campaign(camp)
        replayer.block_ip(ip)
    return firewall_webhook(ip, analyst)