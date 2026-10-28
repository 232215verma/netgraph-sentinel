import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AlertDrawer from "./components/AlertDrawer";
import LiveGraph, { GraphNode, GraphLink } from "./components/LiveGraph";
import ActivityChart, { ActivityPoint } from "./components/ActivityChart";
// ARENA: ARENA_LAUNCH_EVENT is fired by the Attack Arena in DemoPanel
import DemoPanel, { ARENA_LAUNCH_EVENT, type ArenaLaunchDetail } from "./components/DemoPanel";
import ThreatTypeMenu from "./components/ThreatTypeMenu";

import { SHOW_SHAPE_EVENT } from "./components/AlertFeed";
import { Alert, WsMessage } from "./types";
import { THREAT_INFO, THREAT_ORDER, severityOf } from "./threatInfo";

const API_BASE = import.meta.env.VITE_API_URL || "https://vyuh-threat-detection.onrender.com";
const WS_BASE = API_BASE.replace(/^http/, "ws");
const RECONNECT_DELAY_MS = 2000;

// How long detection events are kept for the live timeline
const HISTORY_KEEP_MS = 15 * 60 * 1000;

// Autonomous monitoring: a new scan starts every 30 s, and the backend is re-checked every 30 s
const LIVE_SEQUENCE = ["full", "portscan", "ddos", "dga", "dnstunnel", "c2", "exfil"];
const LIVE_INTERVAL_MS = 30_000; // a new scan starts every 30 seconds, on its own
const POLL_MS = 30_000;

// Scenario button key -> threat type (so the chart can use that scenario's own color)
const SCENARIO_TYPE: Record<string, string> = {
  portscan: "PortScan",
  dga: "DGA",
  dnstunnel: "DNSTunneling",
  c2: "C2Beaconing",
  exfil: "Exfiltration",
  ddos: "DDoS",
};

// What the topology graph is showing, in plain words
// SHAPES: every threat type now has its own shape
const SHAPE_NAME: Record<string, string> = {
  PortScan: "star: one host probing many hosts and ports",
  DDoS: "funnel: many sources converging on one target",
  DGA: "comb: one host fanning out to many one-off destinations",
  C2Beaconing: "ring: a repeating check-in and reply loop with one controller",
  DNSTunneling: "pipeline: oversized DNS queries flowing to one resolver",
  Exfiltration: "diamond: a burst of outbound transfers to one external destination",
};

// SHAPES: only these shapes have a single "centre" node (the scanner / the target / the bot)
const CENTERED_TYPES = new Set(["PortScan", "DDoS", "DGA"]);

// ---------------------------------------------------------------------------
// The topology graph shows ONE shape: the threat being detected right now.
// ---------------------------------------------------------------------------
interface ShapeState {
  type: string | null;
  nodes: GraphNode[];
  links: GraphLink[];
}

const EMPTY_SHAPE: ShapeState = { type: null, nodes: [], links: [] };

/** Nodes + links one alert describes: the backend's full shape if present, else a plain source -> target edge. */
function shapeParts(alert: Alert): { nodes: GraphNode[]; links: GraphLink[] } {
  if (alert.graph && alert.graph.links.length > 0) {
    return { nodes: alert.graph.nodes, links: alert.graph.links };
  }
  const nodes: GraphNode[] = [];
  for (const id of [alert.source, alert.target]) {
    if (id) nodes.push({ id, flagged: true, types: [alert.type], primaryType: alert.type });
  }
  const links: GraphLink[] =
    alert.source && alert.target ? [{ source: alert.source, target: alert.target, type: alert.type }] : [];
  return { nodes, links };
}

/** Same threat type -> grow the current shape. Different type -> replace it with the new one. */
function mergeAlertIntoShape(prev: ShapeState, alert: Alert): ShapeState {
  const parts = shapeParts(alert);
  const base: ShapeState = prev.type === alert.type ? prev : { type: alert.type, nodes: [], links: [] };

  const nodeMap = new Map<string, GraphNode>(base.nodes.map((n) => [n.id, n]));
  for (const n of parts.nodes) if (!nodeMap.has(n.id)) nodeMap.set(n.id, n);

  const linkMap = new Map<string, GraphLink>(base.links.map((l) => [`${l.source}->${l.target}`, l]));
  for (const l of parts.links) {
    const key = `${l.source}->${l.target}`;
    if (!linkMap.has(key)) linkMap.set(key, l);
  }

  return { type: alert.type, nodes: Array.from(nodeMap.values()), links: Array.from(linkMap.values()) };
}

export default function App() {
  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [shape, setShape] = useState<ShapeState>(EMPTY_SHAPE);
  const [status, setStatus] = useState("Idle");
  const [totalFlows, setTotalFlows] = useState<number | null>(null);
  const [flowsSoFar, setFlowsSoFar] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [history, setHistory] = useState<ActivityPoint[]>([]);
  const [stageText, setStageText] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [presetType, setPresetType] = useState<string | null>(null);
  const [seenCount, setSeenCount] = useState(0);
  const [focusType, setFocusType] = useState<string | null>(null);
  const [liveMode, setLiveMode] = useState(true); // autonomous by default

  // Responsive chart height only — purely visual, no detection logic involved.
  const [chartHeight, setChartHeight] = useState(() =>
    typeof window !== "undefined" && window.innerWidth <= 560 ? 180 : 320
  );
  useEffect(() => {
    const onResize = () => setChartHeight(window.innerWidth <= 560 ? 180 : 320);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const flowsRef = useRef(0);
  const liveModeRef = useRef(true);
  const isRunningRef = useRef(false);
  const lastLaunchRef = useRef(0);
  const seqRef = useRef(0);
  const alertsRef = useRef<Alert[]>([]);
  const launchNextRef = useRef<() => void>(() => {});
  // ARENA: while true, only messages tagged origin="arena" are shown (live monitoring is ignored)
  const arenaLockRef = useRef(false);
  liveModeRef.current = liveMode;
  isRunningRef.current = isRunning;
  alertsRef.current = alerts;
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);

  // The graph drawn on screen = the current shape, with its centre node marked.
  const graph = useMemo(() => {
    const degree = new Map<string, number>();
    for (const l of shape.links) {
      degree.set(l.source, (degree.get(l.source) ?? 0) + 1);
      degree.set(l.target, (degree.get(l.target) ?? 0) + 1);
    }
    let centerId: string | null = null;
    let best = 2; // a centre needs at least 3 connections
    // SHAPES: ring / pipeline / diamond have two equal endpoints, so only star, funnel and comb get a centre
    if (shape.type && CENTERED_TYPES.has(shape.type)) {
      for (const [id, d] of degree) {
        if (d > best) {
          best = d;
          centerId = id;
        }
      }
    }
    const nodes: GraphNode[] = shape.nodes.map((n) => ({ ...n, center: n.id === centerId }));
    return { nodes, links: shape.links };
  }, [shape]);

  // Total distinct hosts across ALL alerts (not just the shape on screen), for the KPI + drawer.
  const flaggedHostCount = useMemo(() => {
    const ids = new Set<string>();
    for (const a of alerts) {
      if (a.source) ids.add(a.source);
      if (a.target) ids.add(a.target);
    }
    return ids.size;
  }, [alerts]);

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of alerts) counts[a.type] = (counts[a.type] || 0) + 1;
    return counts;
  }, [alerts]);

  const criticalCount = useMemo(
    () => alerts.filter((a) => severityOf(a.confidence) === "critical").length,
    [alerts]
  );

  const pushHistoryPoint = useCallback((alertType: string) => {
    const now = Date.now();
    setHistory((prev) => [...prev.filter((p) => now - p.t < HISTORY_KEEP_MS), { t: now, type: alertType }]);
  }, []);

  // Keep the "new alerts" indicator in sync while the drawer is open.
  useEffect(() => {
    if (drawerOpen) setSeenCount(alerts.length);
  }, [drawerOpen, alerts.length]);

  // "Show on graph" button on an alert card: draw exactly that alert's shape.
  useEffect(() => {
    const onShowShape = (e: Event) => {
      const alert = (e as CustomEvent<Alert>).detail;
      if (!alert) return;
      setShape(mergeAlertIntoShape(EMPTY_SHAPE, alert));
      setDrawerOpen(false);
    };
    window.addEventListener(SHOW_SHAPE_EVENT, onShowShape);
    return () => window.removeEventListener(SHOW_SHAPE_EVENT, onShowShape);
  }, []);

  // ARENA: an Attack Arena launch -> pause live monitoring, clear the graph, show only Arena events.
  useEffect(() => {
    const onArenaLaunch = (e: Event) => {
      const d = (e as CustomEvent<ArenaLaunchDetail>).detail;
      arenaLockRef.current = true;
      liveModeRef.current = false;
      setLiveMode(false);
      setFocusType(null);
      setShape(EMPTY_SHAPE);
      setIsComplete(false);
      setStageText(null);
      lastLaunchRef.current = Date.now();
      if (d) {
        const label = THREAT_INFO[d.type]?.label ?? d.type;
        setStatus(
          d.mode === "killchain"
            ? `Attack Arena: kill chain from ${d.attacker_ip}`
            : `Attack Arena: ${label}${d.type === "DDoS" ? ` on ${d.target_ip}` : ` from ${d.attacker_ip}`}`
        );
      }
    };
    window.addEventListener(ARENA_LAUNCH_EVENT, onArenaLaunch);
    return () => window.removeEventListener(ARENA_LAUNCH_EVENT, onArenaLaunch);
  }, []);

  useEffect(() => {
    fetch(`${API_BASE}/api/alerts`)
      .then((res) => {
        if (!res.ok) throw new Error();
        return res.json();
      })
      .then((data: { alerts: Alert[] }) => {
        setAlerts(data.alerts);
        setSeenCount(data.alerts.length);
      })
      .catch(() => setErrorBanner("Unable to load alert history. Verify that the backend is running on port 8000."));
  }, []);

  useEffect(() => {
    let cancelled = false;

     function connect() {
     const ws = new WebSocket(`${WS_BASE}/ws/live`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setErrorBanner(null);
      };
      ws.onclose = () => {
        setConnected(false);
        if (!cancelled) reconnectTimerRef.current = window.setTimeout(connect, RECONNECT_DELAY_MS);
      };
      ws.onerror = () => setConnected(false);

      ws.onmessage = (event) => {
        const msg: WsMessage = JSON.parse(event.data);

        // ARENA: while an Arena attack is on screen, drop everything that is not from the Arena
        const origin = (msg as unknown as { origin?: string }).origin;
        if (arenaLockRef.current && origin !== "arena") return;

        switch (msg.event) {
          case "stage_announcement":
            setStageText(msg.text ?? null);
            break;
          case "simulation_started":
            setStatus(`Analyzing ${msg.total_flows?.toLocaleString()} flows`);
            setTotalFlows(msg.total_flows ?? null);
            setIsComplete(false);
            setIsRunning(true);
            setShape(EMPTY_SHAPE); // new run -> clear the previous attack's shape
            break;
          case "batch_processed":
            flowsRef.current = msg.flows_so_far ?? 0;
            setFlowsSoFar(flowsRef.current);
            setStatus(`Analyzed ${flowsRef.current.toLocaleString()} flows`);
            break;
          case "alert":
            if (msg.alert) {
              setAlerts((prev) => [msg.alert!, ...prev]);
              setShape((prev) => mergeAlertIntoShape(prev, msg.alert!));
              pushHistoryPoint(msg.alert.type);
            }
            break;
          case "simulation_complete":
            setStatus(`Run complete · ${msg.total_alerts} unique detections`);
            setIsComplete(true);
            setIsRunning(false);
            break;
        }
      };
    }

    connect();
    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [pushHistoryPoint]);

  const resetForNewRun = () => {
    arenaLockRef.current = false; // ARENA: any normal run (or Clear) releases the Arena lock
    lastLaunchRef.current = Date.now();
    setIsComplete(false);
    setStageText(null);
    flowsRef.current = 0;
    setFlowsSoFar(0);
  };

  const post = async (path: string, body?: unknown) => {
    const res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    if (!res.ok) throw new Error();
  };

  const startSimulation = async () => {
    resetForNewRun();
    setFocusType(null);
    setShape(EMPTY_SHAPE);
    setStatus("Starting dataset replay…");
    setErrorBanner(null);
    try {
      await post("/api/start-simulation");
    } catch {
      setErrorBanner("Unable to start the replay. Verify that the backend is running.");
      setStatus("Idle");
    }
  };

  const triggerAttack = async (attack: string) => {
    resetForNewRun();
    setFocusType(liveModeRef.current ? null : SCENARIO_TYPE[attack] ?? null);
    setShape(EMPTY_SHAPE);
    setStatus("Launching scenario…");
    setErrorBanner(null);
    try {
      await post("/api/demo/attack", { attack });
    } catch {
      setErrorBanner("Unable to launch the scenario. Verify that the backend is running.");
      setStatus("Idle");
    }
  };

  const triggerFullDemo = async () => {
    resetForNewRun();
    setFocusType(null);
    setShape(EMPTY_SHAPE);
    setStatus("Running scripted demo…");
    setErrorBanner(null);
    try {
      await post("/api/demo/full");
    } catch {
      setErrorBanner("Unable to start the scripted demo. Verify that the backend is running.");
      setStatus("Idle");
    }
  };

  const clearAll = async () => {
    try {
      await fetch(`${API_BASE}/api/alerts`, { method: "DELETE" });
    } catch {
      setErrorBanner("Unable to reach the backend to clear alerts.");
    }
    setHistory([]);
    setFocusType(null);
    setAlerts([]);
    setShape(EMPTY_SHAPE);
    setSeenCount(0);
    setTotalFlows(null);
    setStatus("Cleared");
    resetForNewRun();
  };

  const toggleLive = () => {
    lastLaunchRef.current = 0; // start the first scan right away
    if (!liveModeRef.current) arenaLockRef.current = false; // ARENA: turning live monitoring back ON releases the lock
    setLiveMode((v) => !v);
  };

  // Always points at the latest trigger functions, so the timer below never uses stale ones.
  launchNextRef.current = () => {
    const step = LIVE_SEQUENCE[seqRef.current % LIVE_SEQUENCE.length];
    seqRef.current += 1;
    if (step === "full") void triggerFullDemo();
    else void triggerAttack(step);
  };

  // Autonomous monitoring: start a scan every 30 s (or right after the previous one ends if it ran longer), forever.
  useEffect(() => {
    if (!liveMode || !connected) return;
    const id = window.setInterval(() => {
      if (isRunningRef.current) return;
      if (arenaLockRef.current) return; // ARENA: never start live scans while an Arena attack is on screen
      if (Date.now() - lastLaunchRef.current < LIVE_INTERVAL_MS) return;
      launchNextRef.current();
    }, 1000);
    return () => clearInterval(id);
  }, [liveMode, connected]);

  // Every 30 s, pull alerts the backend has that this page has not seen yet (needs alerts to carry an id).
  useEffect(() => {
    const id = window.setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/alerts`);
        if (!res.ok) return;
        const data: { alerts: Alert[] } = await res.json();
        const known = new Set<unknown>(alertsRef.current.map((a) => a.id).filter((x) => x != null));
        const fresh = data.alerts.filter((a) => a.id != null && !known.has(a.id));
        if (fresh.length === 0) return;
        setAlerts((prev) => [...fresh, ...prev]);
        fresh.forEach((a) => pushHistoryPoint(a.type));
      } catch {
        /* backend unreachable, try again on the next tick */
      }
    }, POLL_MS);
    return () => clearInterval(id);
  }, [pushHistoryPoint]);

  const unseen = Math.max(0, alerts.length - seenCount);
  const categories = Object.keys(typeCounts).length;

  const shapeTitle = shape.type ? THREAT_INFO[shape.type]?.label ?? shape.type : null;
  const shapeSub = shape.type
    ? `${shapeTitle}: ${SHAPE_NAME[shape.type] ?? "pattern detected"} (${graph.nodes.length} nodes)`
    : "The shape of the threat being detected right now";

  return (
    <div className="app">
      {errorBanner && <div className="error-banner">{errorBanner}</div>}

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round">
              <circle cx="5" cy="6" r="2.2" />
              <circle cx="19" cy="7" r="2.2" />
              <circle cx="12" cy="18" r="2.2" />
              <path d="M7 6.6l10 .4M6.4 8l4.6 8.2M17.8 8.9l-4.6 7.3" />
            </svg>
          </div>
          <div>
            <div className="brand-name">VYUH</div>
            <div className="brand-sub">व्यूह — Graph-Based Passive Threat Detection</div>
          </div>
        </div>

        <div className="conn">
          <span className={`conn-dot ${connected ? "on" : ""}`} />
          {connected ? "Connected" : "Reconnecting…"}
        </div>

        <div className="topbar-status">
          {isRunning && <span className="spinner" />}
          {status}
        </div>

        <button className="btn btn-ghost" onClick={clearAll}>
          Clear
        </button>
        <button className="btn btn-alert" onClick={() => setDrawerOpen(true)}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
            <path d="M13.7 21a2 2 0 01-3.4 0" />
          </svg>
          <span>Alert Center</span>
          <span className={`count-badge ${unseen > 0 ? "new" : ""}`}>{alerts.length}</span>
        </button>
      </header>

      <DemoPanel
        onTriggerAttack={triggerAttack}
        onTriggerFullDemo={triggerFullDemo}
        onReplay={startSimulation}
        busy={isRunning}
        liveMode={liveMode}
        onToggleLive={toggleLive}
      />

      {stageText && <div className="stage-banner">{stageText.replace(/^[^A-Za-z0-9]+/, "")}</div>}

      <section className="kpis">
        <div className="kpi" style={{ ["--kpi-color" as string]: "#e8a33c" }}>
          <div className="kpi-label">Total alerts</div>
          <div className="kpi-value">{alerts.length}</div>
          <div className="kpi-sub">
            {categories} threat {categories === 1 ? "category" : "categories"}
          </div>
        </div>
        <div className="kpi" style={{ ["--kpi-color" as string]: "#f43f5e" }}>
          <div className="kpi-label">Critical</div>
          <div className="kpi-value">{criticalCount}</div>
          <div className="kpi-sub">Confidence ≥ 90%</div>
        </div>
        <div className="kpi" style={{ ["--kpi-color" as string]: "#a78bfa" }}>
          <div className="kpi-label">Hosts flagged</div>
          <div className="kpi-value">{flaggedHostCount}</div>
          <div className="kpi-sub">Distinct IP addresses</div>
        </div>
        <div className="kpi" style={{ ["--kpi-color" as string]: "#34d399" }}>
          <div className="kpi-label">Flows analyzed</div>
          <div className="kpi-value">{flowsSoFar.toLocaleString()}</div>
          <div className="kpi-sub">
            {totalFlows ? `of ${totalFlows.toLocaleString()} in this run` : "No run in progress"}
          </div>
        </div>
      </section>

      <section className="activity-section">
        <div className="stage-head">
          <div>
            <div className="stage-title">Detection activity</div>
            <div className="stage-sub">Live timeline of detections, moving continuously with a marker every 30 seconds. A single scenario shows its own color, a full scan shows one wave per threat type</div>
          </div>
        </div>
        <div className="activity-body">
          <ActivityChart data={history} height={chartHeight} focusType={focusType} totalAlerts={alerts.length} />
        </div>
      </section>

      <section className="stage">
        <div className="stage-head">
          <div>
            <div className="stage-title">Network topology</div>
            <div className="stage-sub">{shapeSub}</div>
          </div>
       <div className="legend">
  {THREAT_ORDER.map((type) => (
    <ThreatTypeMenu
      key={type}
      type={type}
      alerts={alerts}
      onViewAll={() => {
        setPresetType(type);
        setDrawerOpen(true);
      }}
    />
  ))}
</div>
        </div>

        {/* SHAPES: shapeType tells the graph which fixed layout to use */}
        <LiveGraph nodes={graph.nodes} links={graph.links} shapeType={shape.type}>
          {graph.nodes.length === 0 && (
            <div className="empty">
              <div className="empty-title">No active threat shape</div>
              <div className="empty-text">
                Launch a scenario from the console above, or replay the dataset, and the shape of the attack will be
                drawn here. You can also open the Alert Center and press "Show on graph" on any past alert.
              </div>
            </div>
          )}
        </LiveGraph>
      </section>

<AlertDrawer
  open={drawerOpen}
  onClose={() => setDrawerOpen(false)}
  alerts={alerts}
  isComplete={isComplete}
  totalFlows={totalFlows}
  flaggedIpCount={graph.nodes.length}
  presetType={presetType}
/>
    </div>
  );
}