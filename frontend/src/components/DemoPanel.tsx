import { useState, type CSSProperties } from "react";
import { THREAT_INFO } from "../threatInfo";
// Phase 1: Attack Arena (launch a single attack or the full kill chain)
import { launchAttack } from "../phase1";

/**
 * Fired after an Arena attack was accepted by the backend. App.tsx listens:
 * it turns live monitoring off, clears the graph and shows ONLY Arena events.
 */
export const ARENA_LAUNCH_EVENT = "netgraph:arena-launch";

export interface ArenaLaunchDetail {
  type: string;
  attacker_ip: string;
  target_ip: string;
  mode: "single" | "killchain";
}

const SCENARIOS: { key: string; type: string }[] = [
  { key: "portscan", type: "PortScan" },
  { key: "dga", type: "DGA" },
  { key: "dnstunnel", type: "DNSTunneling" },
  { key: "c2", type: "C2Beaconing" },
  { key: "exfil", type: "Exfiltration" },
  { key: "ddos", type: "DDoS" },
];

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

interface Props {
  onTriggerAttack: (key: string) => void;
  onTriggerFullDemo: () => void;
  onReplay: () => void;
  busy: boolean;
  liveMode: boolean;
  onToggleLive: () => void;
}

export default function DemoPanel({ onTriggerAttack, onTriggerFullDemo, onReplay, busy, liveMode, onToggleLive }: Props) {
  // Phase 1: Attack Arena state
  const [arenaType, setArenaType] = useState("PortScan");
  const [attackerIp, setAttackerIp] = useState("10.0.0.66");
  const [targetIp, setTargetIp] = useState("10.0.0.10");
  const [arenaBusy, setArenaBusy] = useState(false);
  const [arenaMsg, setArenaMsg] = useState<string | null>(null);
  const ipsValid = IPV4.test(attackerIp) && IPV4.test(targetIp) && attackerIp !== targetIp;
  const isDdos = arenaType === "DDoS";

  const runArena = async (mode: "single" | "killchain") => {
    setArenaBusy(true);
    setArenaMsg(null);
    try {
      await launchAttack({ type: arenaType, attacker_ip: attackerIp, target_ip: targetIp, mode });

      // Tell App.tsx: switch live monitoring off and draw only this attack's graph.
      window.dispatchEvent(
        new CustomEvent<ArenaLaunchDetail>(ARENA_LAUNCH_EVENT, {
          detail: { type: arenaType, attacker_ip: attackerIp, target_ip: targetIp, mode },
        })
      );

      setArenaMsg(
        mode === "killchain"
          ? `Kill chain started from ${attackerIp}: scan, then C2, then exfiltration (about 25 seconds). Live monitoring is paused.`
          : `${THREAT_INFO[arenaType]?.label ?? arenaType} launched${isDdos ? "" : ` from ${attackerIp}`}. Live monitoring is paused.`
      );
    } catch {
      setArenaMsg(
        "Could not launch. The backend may be down, or this attacker IP is already quarantined (use Clear to reset)."
      );
    } finally {
      setArenaBusy(false);
    }
  };

  return (
    <div className="console">
      <span className="console-label">Scenario Console</span>
      {SCENARIOS.map((s) => {
        const info = THREAT_INFO[s.type];
        return (
          <button
            key={s.key}
            className="chip"
            disabled={busy}
            onClick={() => onTriggerAttack(s.key)}
            style={{ "--chip-color": info.color } as CSSProperties}
          >
            <span className="chip-dot" />
            {info.label}
          </button>
        );
      })}
      <div className="console-actions">
        <button
          className={`btn btn-ghost ${liveMode ? "btn-live-on" : ""}`}
          onClick={onToggleLive}
          title="Keep scanning continuously, one scenario after another"
        >
          <span className="live-dot" />
          {liveMode ? "Live monitoring: ON" : "Live monitoring: OFF"}
        </button>
        <button className="btn btn-ghost" disabled={busy} onClick={onReplay}>
          Replay dataset
        </button>
        <button className="btn btn-primary" disabled={busy} onClick={onTriggerFullDemo}>
          Run scripted demo
        </button>
      </div>

      {/* Phase 1: Attack Arena */}
      <div
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 8,
          marginTop: 10,
          paddingTop: 10,
          borderTop: "1px solid rgba(148,164,185,0.18)",
        }}
      >
        <span className="console-label">Attack Arena</span>

        <select className="select" value={arenaType} onChange={(e) => setArenaType(e.target.value)}>
          {SCENARIOS.map((s) => (
            <option key={s.key} value={s.type}>
              {THREAT_INFO[s.type]?.label ?? s.type}
            </option>
          ))}
        </select>

        <input
          className="select"
          style={{ width: 140, fontFamily: "inherit", opacity: isDdos ? 0.5 : 1 }}
          value={attackerIp}
          onChange={(e) => setAttackerIp(e.target.value.trim())}
          placeholder="Attacker IP (any)"
          aria-label="Attacker IP"
          title={isDdos ? "A DDoS has many sources, so the attacker IP is not used" : "Internal or external IPv4 address"}
        />
        <input
          className="select"
          style={{ width: 140, fontFamily: "inherit" }}
          value={targetIp}
          onChange={(e) => setTargetIp(e.target.value.trim())}
          placeholder="Target IP"
          aria-label="Target IP"
        />

        <button className="btn btn-ghost" disabled={arenaBusy || !ipsValid} onClick={() => runArena("single")}>
          Launch attack
        </button>
        <button className="btn btn-primary" disabled={arenaBusy || !ipsValid} onClick={() => runArena("killchain")}>
          Run kill chain
        </button>

        {!ipsValid && (
          <span style={{ fontSize: 12, opacity: 0.7 }}>Enter two different valid IPv4 addresses.</span>
        )}
        {isDdos && ipsValid && (
          <span style={{ fontSize: 12, opacity: 0.7 }}>DDoS uses many sources; only the target IP matters.</span>
        )}
        {arenaMsg && <span style={{ fontSize: 12, opacity: 0.85 }}>{arenaMsg}</span>}
        <span style={{ fontSize: 11, opacity: 0.55, width: "100%" }}>
          Any IPv4 works, internal or external. The data is synthetic: no traffic is ever sent to these addresses.
        </span>
      </div>
    </div>
  );
}