import { useState } from "react";
import { DEMO_MODE, tamperLatestAlert, useLedgerStatus, verifyLedgerNow } from "../phase1";

const OK_COLOR = "#34d399";
const BAD_COLOR = "#ef4444";

/** Small pill used inside SummaryReport. Renders nothing until the backend answers. */
export function LedgerBadge() {
  const status = useLedgerStatus();
  if (!status) return null;
  const color = status.ok ? OK_COLOR : BAD_COLOR;
  return (
    <span className="summary-tag" style={{ borderColor: `${color}66`, color }}>
      <span className="legend-dot" style={{ background: color }} />
      {status.ok ? `Ledger verified · ${status.checked} records` : `Ledger broken at #${status.broken_at}`}
    </span>
  );
}

export default function LedgerPanel() {
  const status = useLedgerStatus();
  const [busy, setBusy] = useState(false);

  // Hidden until the backend ledger exists, so the drawer looks unchanged without it.
  if (!status) return null;

  const color = status.ok ? OK_COLOR : BAD_COLOR;

  const verify = async () => {
    setBusy(true);
    try {
      await verifyLedgerNow();
    } finally {
      setBusy(false);
    }
  };

  const tamper = async () => {
    if (!window.confirm("Demo only: modify a stored alert to show that tampering is detected?")) return;
    setBusy(true);
    try {
      await tamperLatestAlert();
    } catch {
      window.alert("Tamper request failed. Is DEMO_MODE enabled on the backend?");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="summary" style={{ marginBottom: 14, borderLeft: `3px solid ${color}` }}>
      <div className="summary-title">Tamper-evident alert ledger</div>

      <p style={{ color, fontWeight: 600, margin: "6px 0" }}>
        {status.ok
          ? `Chain intact: ${status.checked} records verified`
          : `Chain broken at record #${status.broken_at}: stored alerts no longer match their hashes`}
      </p>

      {status.head && (
        <p style={{ fontSize: 12, opacity: 0.75, margin: "4px 0" }}>
          Chain head: <code>{status.head.slice(0, 20)}…</code>
        </p>
      )}

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={verify}>
          {busy ? "Working…" : "Verify ledger"}
        </button>
        {DEMO_MODE && (
          <button className="btn btn-ghost btn-sm" disabled={busy} onClick={tamper}>
            Tamper (demo)
          </button>
        )}
      </div>
    </div>
  );
}