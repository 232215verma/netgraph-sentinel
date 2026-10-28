import { Alert } from "../types";
import { THREAT_INFO } from "../threatInfo";
// Phase 1: campaign + ledger status in the run summary
import { CampaignSummaryLine } from "./CampaignTimeline";
import { LedgerBadge } from "./LedgerPanel";

interface Props {
  alerts: Alert[];
  totalFlows: number | null;
  flaggedIpCount: number;
}

export default function SummaryReport({ alerts, totalFlows, flaggedIpCount }: Props) {
  if (alerts.length === 0) return null;

  const typeCounts: Record<string, number> = {};
  for (const a of alerts) typeCounts[a.type] = (typeCounts[a.type] || 0) + 1;

  const top = [...alerts].sort((a, b) => b.confidence - a.confidence)[0];
  const topInfo = THREAT_INFO[top.type];
  const categories = Object.keys(typeCounts).length;

  return (
    <div className="summary">
      <div className="summary-title">Run summary</div>
      <p>
        {totalFlows !== null && (
          <>
            <b>{totalFlows.toLocaleString()}</b> network flows were analyzed.{" "}
          </>
        )}
        <b>{categories}</b> threat {categories === 1 ? "category was" : "categories were"} identified across{" "}
        <b>{flaggedIpCount}</b> hosts.
      </p>
      <p>
        Highest-severity finding: <b>{topInfo?.label ?? top.type}</b>
        {top.source && (
          <>
            {" "}from <code>{top.source}</code>
          </>
        )}
        {top.target && (
          <>
            {" "}targeting <code>{top.target}</code>
          </>
        )}{" "}
        at <b>{(top.confidence * 100).toFixed(0)}%</b> confidence.
      </p>

      {/* Phase 1 */}
      <CampaignSummaryLine />

      <div className="summary-tags">
        {Object.entries(typeCounts).map(([type, count]) => {
          const info = THREAT_INFO[type];
          if (!info) return null;
          return (
            <span key={type} className="summary-tag">
              <span className="legend-dot" style={{ background: info.color }} />
              {info.label} · {count}
            </span>
          );
        })}
        {/* Phase 1 */}
        <LedgerBadge />
      </div>
    </div>
  );
}