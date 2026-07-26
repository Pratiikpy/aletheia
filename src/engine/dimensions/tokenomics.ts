import type { DimensionScore, Signal, Evidence, VerdictLabel } from "../../types/verdict.js";
import type { RawContext } from "../context.js";

function ev(source: string, detail: string, extra: Partial<Evidence> = {}): Evidence {
  return { source, detail, observed_at: new Date().toISOString(), ...extra };
}
function sig(code: string, severity: 1 | 2 | 3 | 4 | 5, confidence: number, finding: string, evidence: Evidence[]): Signal {
  return { code, severity, dimension: "tokenomics", is_hard_flag: false, confidence, finding, evidence };
}

/**
 * Tokenomics dimension: distribution & valuation health (distinct from security's rug flags).
 * top-10 concentration, creator/team holdings, FDV-vs-liquidity (paper valuation / exit feasibility), LP lock.
 */
export function scoreTokenomics(ctx: RawContext): DimensionScore {
  const freshness = new Date().toISOString();
  const g = ctx.goplus.data ?? {};
  const signals: Signal[] = [];
  const pctNum = (v: any) => (parseFloat(v) || 0);

  // top-10 holder concentration (distribution health) — exclude LP pools, burn, locked, contract wallets
  const BURN = new Set(["0x000000000000000000000000000000000000dead", "0x0000000000000000000000000000000000000000"]);
  const isNonDump = (h: any) => h.is_contract === "1" || h.is_contract === 1 || h.is_locked === true || h.is_locked === "1" || BURN.has((h.address || "").toLowerCase());
  const holders = (Array.isArray(g.holders) ? g.holders : []).filter((h: any) => !isNonDump(h));
  const top10 = holders.slice(0, 10).reduce((s: number, h: any) => s + pctNum(h.percent), 0);
  if (holders.length && !ctx.established) {
    if (top10 >= 0.9) signals.push(sig("extreme_concentration", 4, 0.75, `Top 10 wallets hold ${(top10 * 100).toFixed(0)}% of supply — a handful of wallets control the token.`, [ev("goplus", `top10=${(top10 * 100).toFixed(0)}%`)]));
    else if (top10 >= 0.7) signals.push(sig("high_concentration", 3, 0.7, `Top 10 wallets hold ${(top10 * 100).toFixed(0)}% of supply.`, [ev("goplus", `top10=${(top10 * 100).toFixed(0)}%`)]));
  }

  // creator holding
  const creatorPct = pctNum(g.creator_percent);
  if (creatorPct >= 0.15 && !ctx.established) {
    signals.push(sig("large_creator_holding", creatorPct >= 0.3 ? 4 : 3, 0.75, `Creator holds ${(creatorPct * 100).toFixed(1)}% of supply — concentrated dump risk.`, [ev("goplus", `creator_percent=${(creatorPct * 100).toFixed(1)}%`)]));
  }

  // FDV vs liquidity — exit feasibility / paper valuation. For established/CEX-listed tokens the
  // measured on-chain pool is only a fraction of real (CEX + multi-pool) liquidity, so a high FDV/liq
  // ratio is a measurement artifact, not a "holders can't exit" risk — skip it.
  const fdv = ctx.market.topPair?.fdv ?? null;
  const liq = ctx.market.totalLiquidityUsd;
  if (fdv && liq > 0 && !ctx.established) {
    const ratio = fdv / liq;
    if (ratio >= 200) signals.push(sig("paper_valuation", 3, 0.7, `FDV ($${fmt(fdv)}) is ${ratio.toFixed(0)}× the liquidity ($${fmt(liq)}) — the valuation cannot be realized; large holders cannot exit without collapsing the price.`, [ev("dexscreener", `fdv/liq=${ratio.toFixed(0)}`)]));
    else if (ratio >= 50) signals.push(sig("thin_backing", 2, 0.6, `FDV is ${ratio.toFixed(0)}× liquidity — thin backing relative to valuation.`, [ev("dexscreener", `fdv/liq=${ratio.toFixed(0)}`)]));
  }

  // LP lock positive
  const lp = Array.isArray(g.lp_holders) ? g.lp_holders : [];
  const lpLocked = lp.reduce((s: number, h: any) => s + (h.is_locked ? pctNum(h.percent) : 0), 0);
  if (lp.length && lpLocked >= 0.9) signals.push(sig("lp_locked", 1, 0.7, `${(lpLocked * 100).toFixed(0)}% of LP is locked/burned.`, [ev("goplus", `lp_locked=${(lpLocked * 100).toFixed(0)}%`)]));

  if (ctx.established) signals.push(sig("established_distribution", 1, 0.7, "Established token — broad distribution and deep markets.", [ev("goplus", `holders=${ctx.holderCount}`)]));

  // if we have essentially no tokenomics data
  if (signals.length === 0 && holders.length === 0 && !fdv) {
    return { key: "tokenomics", verdict: "CAUTION", score: 55, confidence: 0.25, freshness, signals: [], summary: "Limited tokenomics data available." };
  }

  let score = 100;
  for (const s of signals) { if (s.code === "lp_locked" || s.code === "established_distribution") continue; score -= s.severity * s.severity * 1.7; }
  score = Math.max(0, Math.round(score));
  const verdict: VerdictLabel = score >= 75 ? "GO" : score >= 45 ? "CAUTION" : "AVOID";
  const confidence = holders.length || fdv ? 0.6 : 0.3;
  const risky = signals.filter((s) => s.code !== "lp_locked" && s.code !== "established_distribution");
  const summary = risky.length ? risky.slice(0, 2).map((s) => s.finding).join(" ") : "Healthy distribution and valuation backing.";

  return { key: "tokenomics", verdict, score, confidence, signals, freshness, summary };
}

const fmt = (n: number) => (n >= 1e9 ? (n / 1e9).toFixed(1) + "B" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(0) + "k" : n.toFixed(0));
