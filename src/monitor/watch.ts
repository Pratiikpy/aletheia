import type { ChainKey } from "../config.js";
import { gather } from "../engine/context.js";
import { buildVerdict } from "../engine/verdict.js";
import type { Verdict } from "../types/verdict.js";

/**
 * Watch-my-bag monitoring. Re-scans a token/wallet and, when something MATERIAL changes, emits a
 * REASONED mini-brief (not a raw event) — what changed, severity, action, evidence. The differentiator:
 * incumbents fire raw events; Aletheia fires a decision-ready brief.
 */

export type Snapshot = {
  chain: ChainKey;
  address: string;
  verdict: Verdict["verdict"];
  score: number;
  liquidityUsd: number;
  hardCodes: string[];
  sevCodes: Record<string, number>; // signal code -> severity
  at: string;
};

export type Alert = {
  severity: 1 | 2 | 3 | 4 | 5;
  code: string;
  title: string;
  brief: string; // 5-line reasoned mini-brief
  action: string;
  subject: { chain: ChainKey; address: string };
  at: string;
};

const rank = (v: Verdict["verdict"]) => (v === "GO" ? 0 : v === "CAUTION" ? 1 : 2);

export async function snapshotOf(chain: ChainKey, address: string): Promise<{ snap: Snapshot; verdict: Verdict }> {
  const ctx = await gather(chain, address, { sim: true });
  const verdict = await buildVerdict(ctx, "full");
  const snap: Snapshot = {
    chain, address,
    verdict: verdict.verdict,
    score: verdict.score,
    liquidityUsd: ctx.market.totalLiquidityUsd,
    hardCodes: verdict.signals.filter((s) => s.is_hard_flag).map((s) => s.code),
    sevCodes: Object.fromEntries(verdict.signals.map((s) => [s.code, s.severity])),
    at: new Date().toISOString(),
  };
  return { snap, verdict };
}

/** Diff two snapshots → reasoned alerts. Pure + deterministic (unit-testable). */
export function diffSnapshots(prev: Snapshot, curr: Snapshot): Alert[] {
  const alerts: Alert[] = [];
  const subject = { chain: curr.chain, address: curr.address };
  const at = curr.at;

  // 1. verdict downgrade
  if (rank(curr.verdict) > rank(prev.verdict)) {
    alerts.push({
      severity: curr.verdict === "AVOID" ? 5 : 4, code: "verdict_downgrade",
      title: `Verdict downgraded ${prev.verdict} → ${curr.verdict}`,
      brief: `A token you're watching just moved from ${prev.verdict} (score ${prev.score}) to ${curr.verdict} (score ${curr.score}). Risk has materially increased since the last check.`,
      action: curr.verdict === "AVOID" ? "Exit / do not add. Re-verify before any trade." : "Reduce exposure and review the new risk before adding.",
      subject, at,
    });
  }

  // 2. new hard flags (e.g., honeypot flip, authority re-added)
  for (const code of curr.hardCodes) {
    if (!prev.hardCodes.includes(code)) {
      alerts.push({
        severity: 5, code: `new_hard_flag:${code}`,
        title: `Critical risk appeared: ${code.replace(/_/g, " ")}`,
        brief: `A NEW critical flag (${code.replace(/_/g, " ")}) was not present at the last scan and is now active. This is the classic "turned malicious after launch" pattern.`,
        action: "Treat as compromised. Exit if holding; do not enter.",
        subject, at,
      });
    }
  }

  // 3. liquidity drop (rug indicator)
  if (prev.liquidityUsd > 0) {
    const drop = 1 - curr.liquidityUsd / prev.liquidityUsd;
    if (drop >= 0.4) {
      alerts.push({
        severity: drop >= 0.7 ? 5 : 4, code: "liquidity_drop",
        title: `Liquidity dropped ${(drop * 100).toFixed(0)}%`,
        brief: `Liquidity fell from $${fmt(prev.liquidityUsd)} to $${fmt(curr.liquidityUsd)} (−${(drop * 100).toFixed(0)}%) since the last check — possible LP pull / rug in progress.`,
        action: "Check if you can still exit; liquidity is leaving.",
        subject, at,
      });
    }
  }

  // 4. new high-severity signal (not already covered by a hard flag)
  for (const [code, sev] of Object.entries(curr.sevCodes)) {
    if (sev >= 4 && !(code in prev.sevCodes) && !curr.hardCodes.includes(code)) {
      alerts.push({
        severity: sev as any, code: `new_risk:${code}`,
        title: `New risk: ${code.replace(/_/g, " ")}`,
        brief: `A new high-severity signal (${code.replace(/_/g, " ")}, severity ${sev}/5) appeared since the last scan.`,
        action: "Review the new risk before your next trade.",
        subject, at,
      });
    }
  }

  return alerts;
}

const fmt = (n: number) => (n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(0) + "k" : n.toFixed(0));

// ---- Watcher runtime ----
export interface AlertSink { (a: Alert): void | Promise<void>; }
export const consoleSink: AlertSink = (a) => console.log(`\n🚨 [${a.severity}/5] ${a.title}\n   ${a.brief}\n   → ${a.action}`);

export class Watcher {
  private snaps = new Map<string, Snapshot>();
  constructor(private sink: AlertSink = consoleSink) {}
  private key(chain: ChainKey, address: string) { return `${chain}:${address.toLowerCase()}`; }

  /** One monitoring tick: snapshot, diff vs last, emit alerts, store. */
  async tick(chain: ChainKey, address: string): Promise<Alert[]> {
    const { snap } = await snapshotOf(chain, address);
    const prev = this.snaps.get(this.key(chain, address));
    const alerts = prev ? diffSnapshots(prev, snap) : [];
    this.snaps.set(this.key(chain, address), snap);
    for (const a of alerts) await this.sink(a);
    return alerts;
  }
}
