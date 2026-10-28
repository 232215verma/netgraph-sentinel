"""
NetGraph Sentinel — Backend (Phase 4/7/8: Full pipeline + demo controls + RAG explanations)

PHASE 1 additions: Attack Arena, node states, campaigns, analyst isolation,
tamper-evident ledger verification (see the "PHASE 1" block).
"""

import asyncio
import ipaddress
import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import init_db, get_alerts, clear_alerts
from pipeline import run_simulation, run_single_attack_demo, run_full_demo_sequence

# PHASE 1
import replayer
from arena import run_kill_chain, run_single_attack, spawn
from campaigns import isolate_node
from database import (
    get_node_states,
    list_campaigns,
    tamper_latest_alert,
    verify_ledger,
)
from traffic_generator import ARENA_KINDS

app = FastAPI(title="NetGraph Sentinel API", version="0.9.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:5174", "http://127.0.0.1:5174",
    ],
    # vercel deployments + any local dev port (Vite moves to 5174, 5175... if 5173 is busy)
    allow_origin_regex=r"https://.*\.vercel\.app|http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@app.on_event("startup")
def on_startup():
    init_db()


class SimulationRequest(BaseModel):
    csv_path: str = "../data/synthetic_traffic.csv"
    batch_size: int = 20
    delay_seconds: float = 0.5


class DemoAttackRequest(BaseModel):
    attack: str  # portscan | ddos | c2 | dga | dnstunnel | exfil


class ExplainRequest(BaseModel):
    type: str
    source: str | None = None
    target: str | None = None
    confidence: float = 0.0
    evidence: list[str] = []


VALID_ATTACKS = {"portscan", "ddos", "c2", "dga", "dnstunnel", "exfil"}


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/hello")
def hello():
    return {"message": "NetGraph Sentinel backend is alive.", "phase": "8 - RAG explanations"}


@app.post("/api/start-simulation")
async def start_simulation(req: SimulationRequest):
    asyncio.create_task(
        run_simulation(req.csv_path, manager, req.batch_size, req.delay_seconds)
    )
    return {"status": "started", "csv_path": req.csv_path}


@app.post("/api/demo/attack")
async def demo_single_attack(req: DemoAttackRequest):
    if req.attack not in VALID_ATTACKS:
        return {"status": "error", "message": f"Unknown attack '{req.attack}'. Valid: {sorted(VALID_ATTACKS)}"}
    asyncio.create_task(run_single_attack_demo(req.attack, manager))
    return {"status": "started", "attack": req.attack}


@app.post("/api/demo/full")
async def demo_full_sequence():
    asyncio.create_task(run_full_demo_sequence(manager))
    return {"status": "started", "mode": "full_demo"}


@app.get("/api/alerts")
def list_alerts(limit: int = 100):
    return {"alerts": get_alerts(limit)}


@app.delete("/api/alerts")
def delete_alerts():
    clear_alerts()
    replayer.clear_blocked()  # PHASE 1: reset = ledger, campaigns, node states AND the simulated firewall
    return {"status": "cleared"}


@app.post("/api/explain-alert")
def explain_alert_endpoint(req: ExplainRequest):
    from rag_engine import explain_alert
    return explain_alert(req.dict())


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ===========================================================================
# PHASE 1: Attack Arena, response, campaigns, ledger
# ===========================================================================
DEMO_MODE = os.getenv("DEMO_MODE", "1") == "1"  # set DEMO_MODE=0 to disable /api/demo/tamper


class AttackLaunchRequest(BaseModel):
    type: str                 # PortScan | DDoS | C2Beaconing | DGA | DNSTunneling | Exfiltration
    attacker_ip: str
    target_ip: str
    mode: str = "single"      # single | killchain


class IsolateRequest(BaseModel):
    ip: str
    analyst: str = "analyst"


def _check_ip(value: str, label: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{label} is not a valid IP address")


@app.post("/api/attack/launch")
async def attack_launch(req: AttackLaunchRequest):
    if req.type not in ARENA_KINDS:
        raise HTTPException(status_code=400, detail=f"Unknown attack type. Valid: {sorted(ARENA_KINDS)}")
    if req.mode not in ("single", "killchain"):
        raise HTTPException(status_code=400, detail="mode must be 'single' or 'killchain'")

    attacker = _check_ip(req.attacker_ip, "attacker_ip")
    target = _check_ip(req.target_ip, "target_ip")
    if attacker == target:
        raise HTTPException(status_code=422, detail="attacker_ip and target_ip must differ")
    if replayer.is_blocked(attacker):
        raise HTTPException(
            status_code=409,
            detail=f"{attacker} is quarantined. Use another attacker IP or reset via DELETE /api/alerts.",
        )

    if req.mode == "killchain":
        spawn(run_kill_chain(attacker, target, manager))
    else:
        spawn(run_single_attack(req.type, attacker, target, manager))
    return {"ok": True, "mode": req.mode, "attacker_ip": attacker}


@app.get("/api/node-states")
def node_states():
    """ip -> state, only for hosts that are not 'normal'."""
    return {"states": get_node_states()}


@app.get("/api/campaigns")
def campaigns():
    return {"campaigns": list_campaigns()}


@app.post("/api/respond/isolate")
def respond_isolate(req: IsolateRequest):
    """
    Analyst response. VYUH stays read-only: this marks the node quarantined and
    calls the SIMULATED out-of-band firewall hook (see campaigns.firewall_webhook).
    """
    ip = _check_ip(req.ip, "ip")
    result = isolate_node(ip, req.analyst)
    return {"ok": True, **result}


@app.get("/api/ledger/verify")
def ledger_verify():
    return verify_ledger()


@app.post("/api/demo/tamper")
def demo_tamper():
    if not DEMO_MODE:
        raise HTTPException(status_code=403, detail="Tamper demo is disabled (DEMO_MODE=0)")
    alert_id = tamper_latest_alert()
    if alert_id is None:
        raise HTTPException(status_code=404, detail="No ledgered alert to tamper with yet")
    return {"ok": True, "tampered_alert_id": alert_id}