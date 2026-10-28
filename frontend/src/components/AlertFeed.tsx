import { useMemo, useState, type CSSProperties } from "react";
import { Alert } from "../types";
import { THREAT_INFO, SEVERITY_META, LAYER_LABELS, severityOf, alertKey } from "../threatInfo";
// Phase 1: node state + campaign badges, and the analyst "Isolate" action
import {
  NODE_STATE_META,
  confirmAndIsolate,
  useCampaigns,
  useNodeStates,
  type Campaign,
} from "../phase1";

const API_BASE = import.meta.env.VITE_API_URL || "https://vyuh-threat-detection.onrender.com";

/** Event name App.tsx listens for: "draw this alert's shape on the topology graph". */
export const SHOW_SHAPE_EVENT = "netgraph:show-shape";

interface Brief {
  explanation: string;
  mitre_id: string | null;
  mitre_name: string | null;
  recommended_action: string | null;
  source: "ollama" | "template";
}

interface Props {
  alerts: Alert[];
}

export default function AlertFeed({ alerts }: Props) {
  const [briefs, setBriefs] = useState<Record<string, Brief>>({});
  const [loading, setLoading] = useState<string | null>(null);

  // Phase 1
  const nodeStates = useNodeStates();
  const campaigns = useCampaigns();
  const [isolating, setIsolating] = useState<string | null>(null);
  const campaignByIp = useMemo(() => {
    const m = new Map<string, Campaign>();
    for (const c of campaigns) m.set(c.src_ip, c);
    return m;
  }, [campaigns]);

  const isolate = async (ip: string) => {
    setIsolating(ip);
    try {
      await confirmAndIsolate(ip);
    } catch {
      window.alert("The response request could not be sent. Check that the backend is running.");
    } finally {
      setIsolating(null);
    }
  };

  const showOnGraph = (alert: Alert) => {
    window.dispatchEvent(new CustomEvent<Alert>(SHOW_SHAPE_EVENT, { detail: alert }));
  };

  const explain = async (alert: Alert) => {
    const key = alertKey(alert);
    setLoading(key);
    try {
      const res = await fetch(`${API_BASE}/api/explain-alert`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: alert.type,
          source: alert.source,
          target: alert.target,
          confidence: alert.confidence,
          evidence: alert.evidence,
        }),
      });
      if (!res.ok) throw new Error();
      const data: Brief = await res.json();
      setBriefs((prev) => ({ ...prev, [key]: data }));
    } catch {
      setBriefs((prev) => ({
        ...prev,
        [key]: {
          explanation: "The explanation service could not be reached. Verify that the backend is running.",
          mitre_id: null,
          mitre_name: null,
          recommended_action: null,
          source: "template",
        },
      }));
    } finally {
      setLoading(null);
    }
  };

  if (alerts.length === 0) {
    return <div className="feed-empty">No alerts match the current filters.</div>;
  }

  return (
    <>
      {alerts.map((alert, i) => {
        const info = THREAT_INFO[alert.type] || {
          label: alert.type,
          color: "#94a3b8",
          mitre: "N/A",
          description: "",
        };
        const sev = SEVERITY_META[severityOf(alert.confidence)];
        const key = alertKey(alert);
        const brief = briefs[key];
        const pct = Math.round(alert.confidence * 100);

        // Phase 1
        const nodeState = alert.source ? nodeStates[alert.source] : undefined;
        const campaign = alert.source ? campaignByIp.get(alert.source) : undefined;
        const canIsolate = !!alert.source && (nodeState === "suspicious" || nodeState === "compromised");

        return (
          <div
            key={alert.id ?? `${key}-${i}`}
            className="alert-card"
            style={{ "--card-color": info.color } as CSSProperties}
          >
            <div className="card-top">
              <span className="card-title">{info.label}</span>
              {info.mitre !== "N/A" && <span className="mitre-tag">{info.mitre}</span>}
              <span className="sev" style={{ background: `${sev.color}22`, color: sev.color }}>
                {sev.label}
              </span>
            </div>

            {/* Phase 1: node state + campaign badges */}
            {((nodeState && nodeState !== "normal") || campaign) && (
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "6px 0" }}>
                {nodeState && nodeState !== "normal" && (
                  <span
                    className="sev"
                    style={{
                      background: `${NODE_STATE_META[nodeState].color}22`,
                      color: NODE_STATE_META[nodeState].color,
                    }}
                  >
                    {NODE_STATE_META[nodeState].label}
                  </span>
                )}
                {campaign && (
                  <span className="mitre-tag">
                    Campaign · {campaign.stages.length} {campaign.stages.length === 1 ? "stage" : "stages"}
                  </span>
                )}
              </div>
            )}

            <div className="conf">
              <div className="conf-bar">
                <div className="conf-fill" style={{ width: `${pct}%`, background: sev.color }} />
              </div>
              <span className="conf-num">{pct}%</span>
            </div>

            <p className="card-desc">{info.description}</p>

            <dl className="meta">
              {alert.source && (
                <>
                  <dt>Source</dt>
                  <dd>{alert.source}</dd>
                </>
              )}
              {alert.target && (
                <>
                  <dt>Target</dt>
                  <dd>{alert.target}</dd>
                </>
              )}
            </dl>

            <div className="layers">
              {alert.layers_agreeing.map((l) => (
                <span key={l} className="layer-tag">
                  {LAYER_LABELS[l] || l}
                </span>
              ))}
            </div>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button className="btn btn-ghost btn-sm" onClick={() => showOnGraph(alert)}>
                Show on graph
              </button>
              {!brief && (
                <button className="btn btn-ghost btn-sm" disabled={loading === key} onClick={() => explain(alert)}>
                  {loading === key ? "Analyzing…" : "Explain alert"}
                </button>
              )}
              {/* Phase 1: analyst response via separate channel */}
              {canIsolate && (
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={isolating === alert.source}
                  onClick={() => isolate(alert.source as string)}
                >
                  {isolating === alert.source ? "Sending…" : "Isolate attacker"}
                </button>
              )}
            </div>

            {brief && (
              <div className="brief">
                <div className="brief-head">
                  Analyst brief
                  {brief.mitre_id && brief.mitre_id !== "N/A" && (
                    <span className="mitre-tag">
                      {brief.mitre_id} · {brief.mitre_name}
                    </span>
                  )}
                </div>
                <div>{brief.explanation}</div>
                {brief.recommended_action && (
                  <div className="brief-action">
                    <b>Recommended action:</b> {brief.recommended_action}
                  </div>
                )}
                {brief.source === "template" && (
                  <div className="brief-note">Generated from the local knowledge base (no LLM connected).</div>
                )}
              </div>
            )}

            <details className="evidence">
              <summary>Evidence ({alert.evidence.length})</summary>
              <ul>
                {alert.evidence.map((e, idx) => (
                  <li key={idx}>{e}</li>
                ))}
              </ul>
            </details>
          </div>
        );
      })}
    </>
  );
}