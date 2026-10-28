import { useState } from "react";
import { THREAT_INFO } from "../threatInfo";
import {
  CAMPAIGN_SEVERITY_COLOR,
  NODE_STATE_META,
  confirmAndIsolate,
  useCampaigns,
  useNodeStates,
  type Campaign,
} from "../phase1";

interface Props {
  /** Optional override; by default campaigns are polled from the backend. */
  campaigns?: Campaign[];
}

const fmtTime = (ts: string) => {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleTimeString();
};

/** One-line summary used inside SummaryReport. */
export function CampaignSummaryLine() {
  const campaigns = useCampaigns();
  if (campaigns.length === 0) return null;
  const multi = campaigns.filter((c) => new Set(c.stages.map((s) => s.tactic)).size >= 2).length;
  return (
    <p>
      <b>{campaigns.length}</b> attack {campaigns.length === 1 ? "campaign" : "campaigns"} reconstructed,{" "}
      <b>{multi}</b> multi-stage.
    </p>
  );
}

export default function CampaignTimeline({ campaigns: override }: Props) {
  const polled = useCampaigns();
  const nodeStates = useNodeStates();
  const [busyIp, setBusyIp] = useState<string | null>(null);

  const list = [...(override ?? polled)].sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""));
  if (list.length === 0) return null;

  const isolate = async (ip: string) => {
    setBusyIp(ip);
    try {
      await confirmAndIsolate(ip);
    } catch {
      window.alert("The response request could not be sent. Check that the backend is running.");
    } finally {
      setBusyIp(null);
    }
  };

  return (
    <div className="summary" style={{ marginBottom: 14 }}>
      <div className="summary-title">Attack campaigns</div>

      {list.map((c) => {
        const sevColor = CAMPAIGN_SEVERITY_COLOR[c.severity] || "#94a3b8";
        const state = nodeStates[c.src_ip];
        const quarantined = state === "quarantined" || c.status === "contained";
        const multi = new Set(c.stages.map((s) => s.tactic)).size >= 2;

        return (
          <div
            key={c.id}
            style={{
              borderTop: "1px solid rgba(148,164,185,0.18)",
              paddingTop: 10,
              marginTop: 10,
              opacity: quarantined ? 0.7 : 1,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <code>{c.src_ip}</code>
              <span className="sev" style={{ background: `${sevColor}22`, color: sevColor }}>
                {c.severity}
              </span>
              {multi && <span className="mitre-tag">MULTI-STAGE</span>}
              {state && state !== "normal" && (
                <span
                  className="sev"
                  style={{
                    background: `${NODE_STATE_META[state].color}22`,
                    color: NODE_STATE_META[state].color,
                  }}
                >
                  {NODE_STATE_META[state].label}
                </span>
              )}
              {!quarantined && (
                <button
                  className="btn btn-ghost btn-sm"
                  style={{ marginLeft: "auto" }}
                  disabled={busyIp === c.src_ip}
                  onClick={() => isolate(c.src_ip)}
                >
                  {busyIp === c.src_ip ? "Sending…" : "Isolate attacker"}
                </button>
              )}
            </div>

            <div style={{ marginTop: 10, marginLeft: 6 }}>
              {c.stages.map((s, i) => {
                const info = THREAT_INFO[s.threat_class];
                const color = info?.color || "#94a3b8";
                const last = i === c.stages.length - 1;
                return (
                  <div
                    key={`${s.tactic_id}-${i}`}
                    style={{
                      position: "relative",
                      paddingLeft: 18,
                      paddingBottom: last ? 0 : 14,
                      borderLeft: last ? "2px solid transparent" : "2px solid rgba(148,164,185,0.3)",
                    }}
                  >
                    <span
                      style={{
                        position: "absolute",
                        left: -6,
                        top: 2,
                        width: 10,
                        height: 10,
                        borderRadius: "50%",
                        background: color,
                        boxShadow: `0 0 0 3px ${color}33`,
                      }}
                    />
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <b>{s.tactic}</b>
                      <span className="mitre-tag">{s.tactic_id}</span>
                      <span style={{ opacity: 0.7, fontSize: 12 }}>{fmtTime(s.first_ts)}</span>
                    </div>
                    <div style={{ fontSize: 13, opacity: 0.85, marginTop: 2 }}>
                      {info?.label ?? s.threat_class} · {Math.round(s.confidence * 100)}% confidence
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}