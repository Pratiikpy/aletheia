import type { DimensionScore, Signal, Evidence, VerdictLabel } from "../../types/verdict.js";
import type { RawContext } from "../context.js";

function ev(source: string, detail: string, extra: Partial<Evidence> = {}): Evidence {
  return { source, detail, observed_at: new Date().toISOString(), ...extra };
}
function sig(code: string, severity: 1 | 2 | 3 | 4 | 5, hard: boolean, confidence: number, finding: string, evidence: Evidence[]): Signal {
  return { code, severity, dimension: "smart_money", is_hard_flag: hard, confidence, finding, evidence };
}

const EXCLUDED: DimensionScore = {
  key: "smart_money", verdict: "CAUTION", score: 50, confidence: 0, freshness: "", signals: [], summary: "",
};

/**
 * Smart-money dimension (OKX Onchain OS): holder clustering + rugPullPercent, bundle/sniper ratios,
 * smart-money buy/sell signals. Requires OKX API creds; returns confidence:0 (excluded) until configured.
 */
export function scoreSmartMoney(ctx: RawContext): DimensionScore {
  if (!ctx.okx) return EXCLUDED;
  const freshness = new Date().toISOString();
  const signals: Signal[] = [];
  const { cluster, signals: smf, memepump } = ctx.okx;

  // Holder clustering / rug-pull probability (Bubblemaps-class)
  const rugPct = num(cluster?.rugPullPercent ?? cluster?.rugPullRatio ?? cluster?.riskyClusterPercent);
  if (rugPct != null) {
    if (rugPct >= 0.5) signals.push(sig("cluster_rug_risk", 5, true, 0.85, `Holder-cluster analysis: ${(rugPct * 100).toFixed(0)}% of supply is in coordinated/insider clusters — high rug probability.`, [ev("okx_onchainos", `rugPullPercent=${(rugPct * 100).toFixed(0)}%`)]));
    else if (rugPct >= 0.25) signals.push(sig("cluster_concentration", 3, false, 0.75, `${(rugPct * 100).toFixed(0)}% of supply sits in linked wallet clusters.`, [ev("okx_onchainos", `rugPullPercent=${(rugPct * 100).toFixed(0)}%`)]));
  }

  // Bundle / sniper ratio at launch (Trench-class)
  const bundlePct = num(memepump?.bundleRatio ?? memepump?.bundlePercent ?? memepump?.bundleBuyRatio);
  if (bundlePct != null && bundlePct >= 0.3) signals.push(sig("bundled_launch", 4, false, 0.8, `${(bundlePct * 100).toFixed(0)}% of supply was bought in bundled launch transactions — insiders front-loaded.`, [ev("okx_onchainos", `bundleRatio=${(bundlePct * 100).toFixed(0)}%`)]));
  const sniperPct = num(memepump?.snieprRatio ?? memepump?.sniperRatio ?? memepump?.apedRatio);
  if (sniperPct != null && sniperPct >= 0.2) signals.push(sig("sniper_heavy", 3, false, 0.75, `${(sniperPct * 100).toFixed(0)}% held by snipers/aped wallets — dump risk.`, [ev("okx_onchainos", `sniperRatio=${(sniperPct * 100).toFixed(0)}%`)]));

  // Smart-money flow signals
  const list: any[] = Array.isArray(smf) ? smf : Array.isArray(smf?.list) ? smf.list : [];
  const buys = list.filter((s) => /buy|accumulat|inflow/i.test(JSON.stringify(s))).length;
  const sells = list.filter((s) => /sell|distribut|outflow/i.test(JSON.stringify(s))).length;
  if (buys + sells >= 3) {
    if (buys > sells * 2) signals.push(sig("smart_money_accumulating", 1, false, 0.7, `Smart money is net accumulating (${buys} buy vs ${sells} sell signals).`, [ev("okx_onchainos", `smart-money buys=${buys} sells=${sells}`)]));
    else if (sells > buys * 2) signals.push(sig("smart_money_distributing", 3, false, 0.7, `Smart money is net distributing (${sells} sell vs ${buys} buy signals) — informed selling.`, [ev("okx_onchainos", `smart-money sells=${sells} buys=${buys}`)]));
  }

  if (signals.length === 0) {
    return { key: "smart_money", verdict: "CAUTION", score: 60, confidence: 0.35, freshness, signals: [], summary: "No notable smart-money or clustering signal." };
  }

  const hard = signals.some((s) => s.is_hard_flag);
  let score = 100;
  for (const s of signals) { if (s.severity === 1) continue; score -= s.severity * s.severity * 1.7; }
  score = Math.max(0, Math.round(score));
  let verdict: VerdictLabel = score >= 75 ? "GO" : score >= 45 ? "CAUTION" : "AVOID";
  if (hard) { verdict = "AVOID"; score = Math.min(score, 15); }
  const risky = signals.filter((s) => s.severity >= 2);
  const summary = risky.length ? risky.slice(0, 2).map((s) => s.finding).join(" ") : signals.map((s) => s.finding).join(" ");
  return { key: "smart_money", verdict, score, confidence: 0.75, signals, freshness, summary };
}

function num(v: any): number | null {
  if (v == null) return null;
  const n = typeof v === "string" ? parseFloat(v) : Number(v);
  if (Number.isNaN(n)) return null;
  // accept either scale: >1 is clearly 0-100 (÷100); a decimal ≤1 is a fraction; a bare integer 1 is
  // treated as 1% (0.01), NOT 100% — the safe direction, so a mis-scaled "1" can't manufacture an AVOID.
  return n > 1 ? n / 100 : n === 1 ? 0.01 : n;
}
