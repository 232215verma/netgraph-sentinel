import { useEffect, useMemo, useState } from "react";
import AlertFeed from "./AlertFeed";
import SummaryReport from "./SummaryReport";
// Phase 1: campaign timeline + tamper-evident ledger panel
import CampaignTimeline from "./CampaignTimeline";
import LedgerPanel from "./LedgerPanel";
import { Alert } from "../types";
import { THREAT_INFO, SEVERITY_META, SEVERITY_ORDER, severityOf, type Severity } from "../threatInfo";

interface Props {
  open: boolean;
  onClose: () => void;
  alerts: Alert[];
  isComplete: boolean;
  totalFlows: number | null;
  flaggedIpCount: number;
  presetType?: string | null;
}

export default function AlertDrawer({ open, onClose, alerts, isComplete, totalFlows, flaggedIpCount, presetType }: Props) {
  const [sev, setSev] = useState<"all" | Severity>("all");
  const [type, setType] = useState("all");

  // When opened from a threat-type menu, jump straight to that filter.
  useEffect(() => {
    if (open && presetType) {
      setType(presetType);
      setSev("all");
    }
  }, [open, presetType]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const types = useMemo(() => Array.from(new Set(alerts.map((a) => a.type))), [alerts]);

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of alerts) {
      const s = severityOf(a.confidence);
      c[s] = (c[s] || 0) + 1;
    }
    return c;
  }, [alerts]);

  const filtered = useMemo(
    () =>
      alerts.filter(
        (a) => (sev === "all" || severityOf(a.confidence) === sev) && (type === "all" || a.type === type)
      ),
    [alerts, sev, type]
  );

  return (
    <>
      <div className={`drawer-backdrop ${open ? "open" : ""}`} onClick={onClose} />
      <aside className={`drawer ${open ? "open" : ""}`} aria-hidden={!open}>
        <div className="drawer-head">
          <div>
            <div className="drawer-title">Alert Center</div>
            <div className="drawer-sub">
              {alerts.length} {alerts.length === 1 ? "detection" : "detections"} · press Esc to close
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close alert center">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round">
              <path d="M6 6l12 12M18 6L6 18" />
            </svg>
          </button>
        </div>

        <div className="drawer-filters">
          <button className={`filter-chip ${sev === "all" ? "active" : ""}`} onClick={() => setSev("all")}>
            All · {alerts.length}
          </button>
          {SEVERITY_ORDER.map((s) => (
            <button
              key={s}
              className={`filter-chip ${sev === s ? "active" : ""}`}
              onClick={() => setSev(s)}
            >
              {SEVERITY_META[s].label} · {sevCounts[s] || 0}
            </button>
          ))}
          <select className="select" value={type} onChange={(e) => setType(e.target.value)}>
            <option value="all">All threat types</option>
            {types.map((t) => (
              <option key={t} value={t}>
                {THREAT_INFO[t]?.label ?? t}
              </option>
            ))}
          </select>
        </div>

        <div className="drawer-body">
          {/* Phase 1: ledger status + attack campaigns (each hides itself until the backend answers) */}
          <LedgerPanel />
          <CampaignTimeline />

          {isComplete && (
            <SummaryReport alerts={alerts} totalFlows={totalFlows} flaggedIpCount={flaggedIpCount} />
          )}
          {alerts.length === 0 ? (
            <div className="feed-empty">
              No detections yet.
              <br />
              Run a scenario from the console to see alerts here.
            </div>
          ) : (
            <AlertFeed alerts={filtered} />
          )}
        </div>
      </aside>
    </>
  );
}