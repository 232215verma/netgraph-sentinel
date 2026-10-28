import { useEffect, useState } from "react";

/* ------------------------------------------------------------------ *
 * Phase 1 shared types, API helpers and polling hooks.
 * Everything here is additive: no existing file depends on it unless
 * it explicitly imports from "../phase1".
 * ------------------------------------------------------------------ */

export const API_BASE: string = import.meta.env.VITE_API_URL || "https://vyuh-threat-detection.onrender.com";

/** Set VITE_DEMO_MODE=0 to hide the "Tamper (demo)" button. */
export const DEMO_MODE: boolean = import.meta.env.VITE_DEMO_MODE !== "0";

export type NodeState = "normal" | "suspicious" | "compromised" | "quarantined";

export const NODE_STATE_META: Record<NodeState, { label: string; color: string }> = {
  normal: { label: "Normal", color: "#34d399" },
  suspicious: { label: "Suspicious", color: "#facc15" },
  compromised: { label: "Compromised", color: "#ef4444" },
  quarantined: { label: "Quarantined", color: "#64748b" },
};

export const CAMPAIGN_SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#facc15",
  low: "#38bdf8",
};

export interface CampaignStage {
  tactic: string; // e.g. "Reconnaissance"
  tactic_id: string; // e.g. "TA0043"
  threat_class: string; // matches THREAT_INFO keys, e.g. "PortScan"
  first_ts: string;
  confidence: number; // 0..1
}

export interface Campaign {
  id: string;
  src_ip: string;
  stages: CampaignStage[];
  severity: string;
  status: "active" | "contained";
  first_seen: string;
  last_seen: string;
}

export interface LedgerStatus {
  ok: boolean;
  checked: number;
  broken_at: number | null;
  head: string | null;
}

export interface AttackRequest {
  type: string; // "PortScan" | "C2Beaconing" | "Exfiltration" | ...
  attacker_ip: string;
  target_ip: string;
  mode: "single" | "killchain";
}

/* ----------------------------- fetch helpers ----------------------------- */

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, init);
  if (!res.ok) throw new Error(String(res.status));
  return (await res.json()) as T;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/* ------------------------- shared polling factory ------------------------- *
 * One interval per endpoint, no matter how many components subscribe.
 * If the backend is not ready, the last value is simply kept.
 * ------------------------------------------------------------------------- */

function makeSharedPoll<T>(path: string, initial: T, intervalMs: number): [() => T, () => Promise<void>] {
  let data = initial;
  const subs = new Set<(d: T) => void>();
  let timer: number | undefined;

  const tick = async () => {
    try {
      const next = await request<T>(path);
      const same = JSON.stringify(next) === JSON.stringify(data);
      data = next;
      if (!same) subs.forEach((s) => s(data));
    } catch {
      /* backend not ready: keep last value */
    }
  };

  const useShared = (): T => {
    const [value, setValue] = useState<T>(data);
    useEffect(() => {
      subs.add(setValue);
      setValue(data);
      if (subs.size === 1) {
        void tick();
        timer = window.setInterval(tick, intervalMs);
      }
      return () => {
        subs.delete(setValue);
        if (subs.size === 0 && timer !== undefined) {
          window.clearInterval(timer);
          timer = undefined;
        }
      };
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    return value;
  };

  return [useShared, tick];
}

/* --------------------------------- hooks --------------------------------- */

const [useNodeStatesRaw, refreshNodeStates] = makeSharedPoll<{ states: Record<string, NodeState> }>(
  "/api/node-states",
  { states: {} },
  2000
);
const [useCampaignsRaw, refreshCampaigns] = makeSharedPoll<{ campaigns: Campaign[] }>(
  "/api/campaigns",
  { campaigns: [] },
  2500
);
const [useLedgerRaw, refreshLedger] = makeSharedPoll<LedgerStatus | null>("/api/ledger/verify", null, 4000);

const EMPTY_STATES: Record<string, NodeState> = {};
const EMPTY_CAMPAIGNS: Campaign[] = [];

/** ip -> node state. Empty until the backend answers. */
export function useNodeStates(): Record<string, NodeState> {
  return useNodeStatesRaw().states ?? EMPTY_STATES;
}

export function useCampaigns(): Campaign[] {
  return useCampaignsRaw().campaigns ?? EMPTY_CAMPAIGNS;
}

/** null until the first successful verify call. */
export function useLedgerStatus(): LedgerStatus | null {
  return useLedgerRaw();
}

/* -------------------------------- actions -------------------------------- */

export function launchAttack(req: AttackRequest) {
  return post<{ ok?: boolean; campaign_id?: string }>("/api/attack/launch", req);
}

/**
 * Analyst response. VYUH itself never blocks anything: this only tells the
 * backend to mark the node and call the (simulated) out-of-band firewall hook.
 */
export async function confirmAndIsolate(ip: string, analyst = "analyst"): Promise<boolean> {
  const ok = window.confirm(
    `Send an out-of-band block request for ${ip}?\n\nVYUH stays read-only. The block is issued through a separate channel (simulated in this demo).`
  );
  if (!ok) return false;
  await post("/api/respond/isolate", { ip, analyst });
  await Promise.all([refreshNodeStates(), refreshCampaigns()]);
  return true;
}

/** Demo only: alters a stored alert so ledger verification fails. */
export async function tamperLatestAlert(): Promise<void> {
  await post("/api/demo/tamper", {});
  await refreshLedger();
}

export const verifyLedgerNow = refreshLedger;