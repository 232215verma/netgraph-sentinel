"""
NetGraph Sentinel — Phase 4: Database

Simple SQLite storage for alerts. One table: alerts.

PHASE 1 additions (marked "PHASE 1"):
  - tamper-evident ledger (SHA-256 hash chain + Merkle roots every 16 records)
  - campaigns table, node_states table
  - save_alert() now appends to the ledger and triggers campaign/node-state updates
"""

import sqlite3
import json
import hashlib
import logging
import os
import threading
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent / "alerts.db"

# PHASE 1 -------------------------------------------------------------------
GENESIS_HASH = "0" * 64
MERKLE_BATCH = 16
_LEDGER_LOCK = threading.RLock()  # serialises ledger appends (chain needs strict order)
_log = logging.getLogger("netgraph.db")
# ---------------------------------------------------------------------------


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            source TEXT,
            target TEXT,
            confidence REAL NOT NULL,
            layers_agreeing TEXT,
            evidence TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # PHASE 1: ledger, merkle roots, campaigns, node states
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            idx INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            payload_hash TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL,
            ts TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS merkle_roots (
            batch_id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_idx INTEGER NOT NULL,
            end_idx INTEGER NOT NULL,
            root TEXT NOT NULL,
            ts TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            src_ip TEXT NOT NULL UNIQUE,
            data_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS node_states (
            ip TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ===========================================================================
# PHASE 1: ledger helpers
# ===========================================================================
def _sha(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _canonical(payload: dict) -> bytes:
    """Deterministic JSON so the same alert always hashes the same."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _payload(alert_type, source, target, confidence, layers, evidence, created_at) -> dict:
    return {
        "type": alert_type,
        "source": source,
        "target": target,
        "confidence": float(confidence),
        "layers_agreeing": list(layers),
        "evidence": list(evidence),
        "created_at": created_at,
    }


def _payload_from_row(row) -> dict:
    return _payload(
        row["type"], row["source"], row["target"], row["confidence"],
        json.loads(row["layers_agreeing"] or "[]"),
        json.loads(row["evidence"] or "[]"),
        row["created_at"],
    )


def _merkle_root(hashes: list[str]) -> str:
    level = list(hashes)
    if not level:
        return GENESIS_HASH
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _append_ledger(conn, alert_id: int, payload: dict) -> None:
    """hash = sha256(prev_hash + sha256(canonical(alert))). Caller holds _LEDGER_LOCK."""
    last = conn.execute("SELECT hash FROM ledger ORDER BY idx DESC LIMIT 1").fetchone()
    prev_hash = last[0] if last else GENESIS_HASH
    payload_hash = _sha(_canonical(payload))
    new_hash = _sha(prev_hash + payload_hash)
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        "INSERT INTO ledger (alert_id, payload_hash, prev_hash, hash, ts) VALUES (?, ?, ?, ?, ?)",
        (alert_id, payload_hash, prev_hash, new_hash, now),
    )

    # every MERKLE_BATCH records, store a Merkle root over that batch
    total = conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
    if total % MERKLE_BATCH == 0:
        batch = conn.execute(
            "SELECT idx, payload_hash FROM ledger ORDER BY idx DESC LIMIT ?", (MERKLE_BATCH,)
        ).fetchall()
        batch.reverse()
        conn.execute(
            "INSERT INTO merkle_roots (start_idx, end_idx, root, ts) VALUES (?, ?, ?, ?)",
            (batch[0][0], batch[-1][0], _merkle_root([b[1] for b in batch]), now),
        )


def verify_ledger() -> dict:
    """
    Re-derive the whole chain from the alerts table and compare.
    Returns {ok, checked, broken_at, head, records}.
    broken_at = ledger index of the first record that does not match.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT idx, alert_id, payload_hash, prev_hash, hash FROM ledger ORDER BY idx"
        ).fetchall()

        prev = GENESIS_HASH
        checked = 0
        for r in rows:
            # 1) chain linkage and hash
            if r["prev_hash"] != prev or _sha(r["prev_hash"] + r["payload_hash"]) != r["hash"]:
                return {"ok": False, "checked": checked, "broken_at": r["idx"],
                        "head": prev if checked else None, "records": len(rows)}
            # 2) the stored alert must still match what was hashed
            a = conn.execute("SELECT * FROM alerts WHERE id = ?", (r["alert_id"],)).fetchone()
            if a is None or _sha(_canonical(_payload_from_row(a))) != r["payload_hash"]:
                return {"ok": False, "checked": checked, "broken_at": r["idx"],
                        "head": prev if checked else None, "records": len(rows)}
            prev = r["hash"]
            checked += 1

        # 3) Merkle batches
        for m in conn.execute("SELECT * FROM merkle_roots ORDER BY batch_id").fetchall():
            hashes = [
                x[0] for x in conn.execute(
                    "SELECT payload_hash FROM ledger WHERE idx BETWEEN ? AND ? ORDER BY idx",
                    (m["start_idx"], m["end_idx"]),
                ).fetchall()
            ]
            if _merkle_root(hashes) != m["root"]:
                return {"ok": False, "checked": checked, "broken_at": m["start_idx"],
                        "head": prev, "records": len(rows)}

        return {"ok": True, "checked": checked, "broken_at": None,
                "head": prev if rows else None, "records": len(rows)}
    finally:
        conn.close()


def tamper_latest_alert() -> int | None:
    """DEMO ONLY: silently change the newest ledgered alert so verify_ledger() fails."""
    with _LEDGER_LOCK:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        row = conn.execute(
            "SELECT a.id, a.confidence FROM alerts a JOIN ledger l ON l.alert_id = a.id "
            "ORDER BY a.id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            conn.close()
            return None
        new_conf = 0.01 if abs(row[1] - 0.01) > 1e-9 else 0.02
        conn.execute("UPDATE alerts SET confidence = ? WHERE id = ?", (new_conf, row[0]))
        conn.commit()
        conn.close()
        return row[0]


# ===========================================================================
# PHASE 1: node states and campaigns
# ===========================================================================
def get_node_state(ip: str) -> str | None:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    row = conn.execute("SELECT state FROM node_states WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return row[0] if row else None


def set_node_state(ip: str, state: str) -> None:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute(
        "INSERT INTO node_states (ip, state, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(ip) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at",
        (ip, state, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def get_node_states() -> dict[str, str]:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute("SELECT ip, state FROM node_states").fetchall()
    conn.close()
    return {ip: state for ip, state in rows}


def get_campaign(src_ip: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    row = conn.execute("SELECT data_json FROM campaigns WHERE src_ip = ?", (src_ip,)).fetchone()
    conn.close()
    return json.loads(row[0]) if row else None


def save_campaign(campaign: dict) -> None:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute(
        "INSERT INTO campaigns (id, src_ip, data_json, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
        (campaign["id"], campaign["src_ip"], json.dumps(campaign),
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def list_campaigns() -> list[dict]:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute("SELECT data_json FROM campaigns ORDER BY updated_at DESC").fetchall()
    conn.close()
    return [json.loads(r[0]) for r in rows]


# ===========================================================================
# Original functions (save_alert extended for PHASE 1)
# ===========================================================================
def save_alert(alert: dict):
    # PHASE 1: whole body runs under the ledger lock; returns the new alert id
    with _LEDGER_LOCK:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        created_at = datetime.now(timezone.utc).isoformat()  # PHASE 1: computed once, reused for the hash
        cur = conn.execute(
            """
            INSERT INTO alerts (type, source, target, confidence, layers_agreeing, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["type"],
                alert.get("source"),
                alert.get("target"),
                alert["confidence"],
                json.dumps(alert.get("layers_agreeing", [])),
                json.dumps(alert.get("evidence", [])),
                created_at,
            ),
        )
        alert_id = cur.lastrowid

        # PHASE 1: tamper-evident ledger entry in the same transaction
        _append_ledger(
            conn, alert_id,
            _payload(alert["type"], alert.get("source"), alert.get("target"), alert["confidence"],
                     alert.get("layers_agreeing", []), alert.get("evidence", []), created_at),
        )
        conn.commit()
        conn.close()

    # PHASE 1: campaign + node-state update. Must never break detection.
    try:
        from campaigns import on_alert_saved
        on_alert_saved({**alert, "id": alert_id, "created_at": created_at}, alert_id)
    except Exception:
        _log.exception("campaign/node-state update failed")

    return alert_id


def get_alerts(limit: int = 100) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "type": row["type"],
            "source": row["source"],
            "target": row["target"],
            "confidence": row["confidence"],
            "layers_agreeing": json.loads(row["layers_agreeing"]),
            "evidence": json.loads(row["evidence"]),
            "created_at": row["created_at"],
        })
    return result


def clear_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM alerts")
    # PHASE 1: a full reset also clears the ledger, campaigns and node states
    conn.execute("DELETE FROM ledger")
    conn.execute("DELETE FROM merkle_roots")
    conn.execute("DELETE FROM campaigns")
    conn.execute("DELETE FROM node_states")
    try:
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('ledger', 'merkle_roots')")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()