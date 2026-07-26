import type { DimensionScore, Signal, Evidence, VerdictLabel } from "../../types/verdict.js";
import type { RawContext } from "../context.js";

function ev(source: string, detail: string, extra: Partial<Evidence> = {}): Evidence {
  return { source, detail, observed_at: new Date().toISOString(), ...extra };
}
function sig(code: string, severity: 1 | 2 | 3 | 4 | 5, is_hard_flag: boolean, confidence: number, finding: string, evidence: Evidence[]): Signal {
  return { code, severity, dimension: "market_structure", is_hard_flag, confidence, finding, evidence };
}

/**
 * Wash-trade detector — manufactured volume has a fingerprint: enormous turnover relative to the pool,
 * a price pinned despite that turnover (real volume moves price), and near-perfectly balanced buy/sell
 * churn (the wallets trade with themselves). We combine those into a 0..1 score. Pure + unit-tested.
 */
export function washTradeScore(input: {
  volumeH24: number;
  liquidityUsd: number;
  priceChangeH24: number | null;
  buys: number;
  sells: number;
}): { score: number; turnover: number; reasons: string[] } {
  const { volumeH24: vol, liquidityUsd: liq, priceChangeH24, buys, sells } = input;
  const reasons: string[] = [];
  if (liq <= 0 || vol <= 0) return { score: 0, turnover: 0, reasons };
  const turnover = vol / liq; // how many times the whole pool "changed hands" in 24h

  let score = 0;
  // 1. extreme turnover — organic pools rarely cycle >10× their liquidity in a day
  if (turnover >= 50) { score += 0.5; reasons.push(`turnover ${turnover.toFixed(0)}× liquidity`); }
  else if (turnover >= 20) { score += 0.35; reasons.push(`turnover ${turnover.toFixed(0)}× liquidity`); }
  else if (turnover >= 10) { score += 0.2; reasons.push(`turnover ${turnover.toFixed(0)}× liquidity`); }

  // 2. price pinned despite heavy volume — real two-way volume moves price; wash volume doesn't
  const pct = priceChangeH24 == null ? null : Math.abs(priceChangeH24);
  if (turnover >= 10 && pct != null && pct < 3) { score += 0.3; reasons.push(`price flat (${pct.toFixed(1)}%) despite ${turnover.toFixed(0)}× turnover`); }

  // 3. eerily balanced churn — self-trading produces near-1:1 buy/sell counts at high volume
  const total = buys + sells;
  if (total >= 100 && turnover >= 10) {
    const balance = Math.min(buys, sells) / Math.max(buys, sells || 1);
    if (balance > 0.9) { score += 0.2; reasons.push(`near-1:1 buy/sell churn (${buys}/${sells})`); }
  }

  return { score: Math.min(1, score), turnover, reasons };
}

/**
 * Market-structure dimension (DexScreener, free): liquidity depth, volume, pair age, buy/sell balance.
 * Thin liquidity / brand-new pair / one-sided flow = risk. Deep liquidity + healthy 2-way volume = ok.
 */
export function scoreMarket(ctx: RawContext): DimensionScore {
  const freshness = new Date().toISOString();
  const m = ctx.market;
  const signals: Signal[] = [];

  if (!m.ok || !m.topPair) {
    // Established tokens (stablecoins/quote assets like USDT) often have no DexScreener *base* pair —
    // that is NOT a risk. Return neutral low-weight, don't penalize.
    if (ctx.established) {
      return {
        key: "market_structure", verdict: "GO", score: 90, confidence: 0.4, freshness,
        signals: [sig("established_no_base_pair", 1, false, 0.6, "No DEX base-pair (this is an established quote/stablecoin asset) — market-structure risk not applicable.", [ev("dexscreener", "no base pair; token is established")])],
        summary: "Established asset; market-structure risk not applicable.",
      };
    }
    return {
      key: "market_structure", verdict: "CAUTION", score: 40, confidence: 0.35, freshness,
      signals: [sig("no_market_data", 3, false, 0.6, `No DEX market found (${m.error ?? "unknown"}) — token may be unlaunched, illiquid, or untradeable.`, [ev("dexscreener", m.error ?? "no pairs")])],
      summary: "No tradeable market found — cannot trade against it.",
    };
  }

  const p = m.topPair;
  const url = p.url;
  const liq = m.totalLiquidityUsd;

  // liquidity depth
  if (liq < 5_000) signals.push(sig("very_low_liquidity", 4, false, 0.85, `Extremely thin liquidity ($${Math.round(liq).toLocaleString()}) — high slippage and easy to drain.`, [ev("dexscreener", `total liquidity $${Math.round(liq)}`, { url })]));
  else if (liq < 30_000) signals.push(sig("low_liquidity", 3, false, 0.8, `Low liquidity ($${Math.round(liq).toLocaleString()}).`, [ev("dexscreener", `total liquidity $${Math.round(liq)}`, { url })]));

  // pair age
  if (p.pairCreatedAt) {
    const ageHours = (Date.now() - p.pairCreatedAt) / 3.6e6;
    if (ageHours < 24) signals.push(sig("brand_new_pair", 3, false, 0.8, `Pair is ${ageHours.toFixed(1)}h old — brand-new, elevated rug risk.`, [ev("dexscreener", `pair age ${ageHours.toFixed(1)}h`, { url })]));
    else if (ageHours < 24 * 7) signals.push(sig("young_pair", 2, false, 0.7, `Pair is ${(ageHours / 24).toFixed(1)} days old.`, [ev("dexscreener", `pair age ${(ageHours / 24).toFixed(1)}d`, { url })]));
  }

  // one-sided flow (many buys, few sells) — can indicate honeypot / manipulated
  const buys = p.txnsH24Buys, sells = p.txnsH24Sells;
  if (buys + sells >= 30 && sells === 0) signals.push(sig("no_sells", 4, false, 0.75, `${buys} buys and 0 sells in 24h — nobody is selling (possible honeypot).`, [ev("dexscreener", `buys=${buys} sells=0 (24h)`, { url })]));
  else if (buys + sells >= 50 && sells / (buys + sells) < 0.1) signals.push(sig("lopsided_flow", 2, false, 0.6, `Very few sells (${sells}) vs buys (${buys}) in 24h.`, [ev("dexscreener", `buys=${buys} sells=${sells}`, { url })]));

  // wash-trade detection (multi-factor: turnover + pinned price + balanced churn). Skipped for
  // established/CEX-listed tokens: a single measured pool isn't representative of their real market,
  // so a high pool-turnover ratio is an artifact, not manufactured volume.
  const wash = washTradeScore({ volumeH24: p.volumeH24, liquidityUsd: liq, priceChangeH24: p.priceChangeH24, buys, sells });
  if (wash.score >= 0.4 && !ctx.established) {
    signals.push(sig("wash_trading", wash.score >= 0.7 ? 3 : 2, false, 0.5 + wash.score * 0.3,
      `Likely wash trading — ${wash.reasons.join("; ")}. Reported volume overstates real demand.`,
      [ev("dexscreener", `washScore=${wash.score.toFixed(2)}: ${wash.reasons.join(" | ")}`, { url })]));
  }

  // positive: healthy market
  if (liq >= 100_000 && sells > 0) signals.push(sig("healthy_market", 1, false, 0.8, `Deep liquidity ($${Math.round(liq).toLocaleString()}) with active two-way trading.`, [ev("dexscreener", `liq $${Math.round(liq)}, buys=${buys}, sells=${sells}`, { url })]));

  // score
  let score = 100;
  for (const s of signals) { if (s.code === "healthy_market") continue; score -= s.severity * s.severity * 1.8; }
  score = Math.max(0, Math.round(score));
  let verdict: VerdictLabel = score >= 75 ? "GO" : score >= 45 ? "CAUTION" : "AVOID";
  const confidence = 0.75;

  const summary = signals.length === 0 || (signals.length === 1 && signals[0]!.code === "healthy_market")
    ? `Liquidity $${Math.round(liq).toLocaleString()}, ${buys}/${sells} buys/sells (24h).`
    : signals.filter(s => s.code !== "healthy_market").slice(0, 2).map((s) => s.finding).join(" ");

  return { key: "market_structure", verdict, score, confidence, signals, freshness, summary };
}
