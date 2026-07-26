import { Verdict, type Verdict as VerdictT, type Signal, type Evidence, type DimensionScore, type DimensionResult, type DimensionKey } from "../types/verdict.js";
import { fuse } from "./fuse.js";
import { explain } from "./explain.js";
import { getSolMintInfo, getSolTopHolders, getSolTradeability, type SolMintInfo, type SolHolders, type SolTradeability } from "../adapters/solana.js";

/**
 * Solana verdict builder — same evidence-linked GO/CAUTION/AVOID envelope as the EVM path, but scored
 * on SPL-native risk vectors (freeze/mint authority, Token-2022 extensions, Jupiter tradeability).
 * Reuses fuse() + explain() so confidence calibration, hard-flag capping, and 0G reasoning all apply.
 */

function ev(source: string, detail: string, extra: Partial<Evidence> = {}): Evidence {
  return { source, detail, observed_at: new Date().toISOString(), ...extra };
}
function sig(code: string, severity: 1 | 2 | 3 | 4 | 5, is_hard_flag: boolean, confidence: number, finding: string, evidence: Evidence[]): Signal {
  return { code, severity, dimension: "security", is_hard_flag, confidence, finding, evidence };
}
const EXPLORER = (mint: string) => `https://solscan.io/token/${mint}`;

// Blue-chip SPL mints that legitimately retain authorities by design (stablecoins/LSTs). For these,
// an active freeze/mint authority is KNOWN centralization, not a rug trap — same idea as EVM `established`.
const ESTABLISHED_MINTS = new Set([
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // USDC
  "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // USDT
  "So11111111111111111111111111111111111111112", // wSOL
  "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So", // mSOL
  "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", // JitoSOL
  "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", // JUP
]);

export type SolContext = { mint: SolMintInfo; holders: SolHolders; trade: SolTradeability };

/** SPL security scoring (pure, unit-testable). */
export function scoreSolSecurity(ctx: SolContext): DimensionScore {
  const freshness = new Date().toISOString();
  const { mint: m, holders: h, trade: t } = ctx;
  const url = EXPLORER(m.mint);
  const established = ESTABLISHED_MINTS.has(m.mint);
  // for an established mint, retained authorities are expected centralization → downgrade to a note.
  const authSev = (base: 1 | 2 | 3 | 4 | 5): 1 | 2 | 3 | 4 | 5 => (established ? 1 : base);
  const authHard = (base: boolean) => (established ? false : base);
  const authNote = (s: string) => (established ? s + " (expected for this established/blue-chip token — not a rug indicator here)" : s);
  const signals: Signal[] = [];

  if (!m.ok) {
    return { key: "security", verdict: "CAUTION", score: 50, confidence: 0.2, freshness,
      signals: [sig("no_mint_data", 2, false, 0.3, `Could not read the SPL mint (${m.error ?? "unknown"}).`, [ev("helius", m.error ?? "no data")])],
      summary: "Insufficient SPL data — treat with caution." };
  }

  // Jupiter honeypot: buyable but not sellable
  if (t.ok && t.isHoneypot) {
    signals.push(sig("sol_honeypot", 5, true, 0.85, "Token can be bought but Jupiter finds NO route to sell it — classic Solana honeypot.",
      [ev("jupiter", "buy route exists, sell route does not", { url })]));
  }
  // freeze authority — the issuer can freeze your token account so you can't sell
  if (m.freezeAuthority) {
    signals.push(sig("freeze_authority_active", authSev(5), authHard(true), 0.9,
      authNote("Freeze authority is active — the issuer can freeze any holder's account, blocking sells at will (Solana honeypot vector)."),
      [ev("helius", `freezeAuthority=${m.freezeAuthority}`, { snippet: `freeze=${m.freezeAuthority}`, url })]));
  }
  // mint authority — supply can be inflated
  if (m.mintAuthority) {
    signals.push(sig("mint_authority_active", authSev(4), false, 0.9,
      authNote("Mint authority is active — supply can be inflated at will (dilution / infinite-mint risk)."),
      [ev("helius", `mintAuthority=${m.mintAuthority}`, { snippet: `mint=${m.mintAuthority}`, url })]));
  }
  // Token-2022 permanent delegate — issuer can move/burn your tokens
  if (m.hasPermanentDelegate) {
    signals.push(sig("permanent_delegate", 5, true, 0.9, "Token-2022 permanent delegate is set — the issuer can move or burn any holder's tokens without consent.",
      [ev("helius", "extension: permanentDelegate", { url })]));
  }
  // Token-2022 transfer hook — arbitrary program on every transfer (can block sells)
  if (m.hasTransferHook) {
    signals.push(sig("transfer_hook", 4, false, 0.8, "Token-2022 transfer-hook is set — an arbitrary program runs on every transfer and can block or tax sells.",
      [ev("helius", "extension: transferHook", { url })]));
  }
  // Token-2022 transfer fee (tax)
  if (m.transferFeeBps != null && m.transferFeeBps > 0) {
    const pct = m.transferFeeBps / 100;
    signals.push(sig("transfer_fee", pct >= 50 ? 5 : pct >= 10 ? 3 : 2, pct >= 50, 0.85,
      `Token-2022 transfer fee of ${pct.toFixed(1)}% is applied on every transfer.`,
      [ev("helius", `transferFeeBps=${m.transferFeeBps}`, { url })]));
  }
  // thin liquidity / high sell impact
  if (t.ok && t.sellable && t.sellPriceImpactPct != null && t.sellPriceImpactPct >= 15) {
    signals.push(sig("high_sell_impact", t.sellPriceImpactPct >= 40 ? 4 : 3, false, 0.7,
      `Selling a modest amount incurs ${t.sellPriceImpactPct.toFixed(1)}% price impact — thin liquidity.`,
      [ev("jupiter", `sell price impact ${t.sellPriceImpactPct.toFixed(1)}%`, { url })]));
  }
  if (t.ok && !t.buyable && !t.sellable) {
    signals.push(sig("not_tradeable", 3, false, 0.6, "No Jupiter route to buy or sell — token is unlaunched or illiquid.",
      [ev("jupiter", "no buy or sell route", { url })]));
  }
  // holder concentration (top account excluding obvious pool is hard to know here — report top1/top10)
  if (h.ok && h.topPct >= 0.5) {
    signals.push(sig("holder_concentration", h.topPct >= 0.8 ? 4 : 3, false, 0.6,
      `Largest account holds ${(h.topPct * 100).toFixed(1)}% of supply (top-10 ${(h.top10Pct * 100).toFixed(1)}%).`,
      [ev("helius", `top1=${(h.topPct * 100).toFixed(1)}%, top10=${(h.top10Pct * 100).toFixed(1)}%`, { url })]));
  }

  // positive: fully renounced + sellable
  const renounced = !m.mintAuthority && !m.freezeAuthority;
  if (renounced && t.ok && t.sellable && signals.length === 0) {
    signals.push(sig("authorities_renounced", 1, false, 0.85, "Mint and freeze authorities are both revoked and the token is sellable on Jupiter.",
      [ev("helius", "mintAuthority=null, freezeAuthority=null", { url })]));
  }

  const hardFlag = signals.some((s) => s.is_hard_flag);
  let score = 100;
  for (const s of signals) { if (s.code === "authorities_renounced") continue; score -= s.severity * s.severity * 1.6; }
  score = Math.max(0, Math.round(score));
  let verdict: DimensionScore["verdict"] = score >= 75 ? "GO" : score >= 45 ? "CAUTION" : "AVOID";
  if (hardFlag) { verdict = "AVOID"; score = Math.min(score, 15); }
  const confidence = t.ok && m.ok ? 0.85 : m.ok ? 0.6 : 0.3;
  const summary = signals.length === 0 ? "No SPL security red flags." : (hardFlag ? "Critical risk: " : "") + signals.slice(0, 3).map((s) => s.finding).join(" ");
  return { key: "security", verdict, score, confidence, signals, freshness, summary };
}

/** SPL market/tradeability scoring (pure). */
export function scoreSolMarket(ctx: SolContext): DimensionScore {
  const freshness = new Date().toISOString();
  const { trade: t, mint: m } = ctx;
  const url = EXPLORER(m.mint);
  const signals: Signal[] = [];
  const mk = (code: string, sev: 1 | 2 | 3 | 4 | 5, conf: number, finding: string, e: Evidence[]): Signal =>
    ({ code, severity: sev, dimension: "market_structure", is_hard_flag: false, confidence: conf, finding, evidence: e });

  if (!t.ok) {
    return { key: "market_structure", verdict: "CAUTION", score: 45, confidence: 0.3, freshness,
      signals: [mk("no_route_data", 2, 0.4, "Could not query Jupiter routes.", [ev("jupiter", t.error ?? "no data")])],
      summary: "Tradeability unknown." };
  }
  if (t.buyable && t.sellable) signals.push(mk("tradeable", 1, 0.8, "Token is both buyable and sellable via Jupiter aggregator.", [ev("jupiter", "buy+sell routes exist", { url })]));
  if (!t.sellable && t.buyable) signals.push(mk("unsellable", 4, 0.8, "No sell route on Jupiter despite a buy route.", [ev("jupiter", "no sell route", { url })]));

  let score = t.buyable && t.sellable ? 90 : t.buyable ? 30 : 45;
  let verdict: DimensionScore["verdict"] = score >= 75 ? "GO" : score >= 45 ? "CAUTION" : "AVOID";
  return { key: "market_structure", verdict, score, confidence: 0.7, signals, freshness, summary: t.buyable && t.sellable ? "Tradeable on Jupiter." : "Limited tradeability." };
}

const COST = { flag: "0.01", full: "0.02", deep: "0.05" } as const;

/** Gather Solana data and build the fused verdict envelope. */
export async function solanaVerdict(mint: string, tier: "flag" | "full" | "deep" = "full"): Promise<VerdictT> {
  const started = Date.now();
  const mintInfo = await getSolMintInfo(mint);
  const [holders, trade] = await Promise.all([
    getSolTopHolders(mint, mintInfo.supply, mintInfo.decimals),
    tier === "flag" ? Promise.resolve({ ok: false, observed_at: new Date().toISOString(), buyable: false, sellable: false, sellPriceImpactPct: null, isHoneypot: false } as SolTradeability) : getSolTradeability(mint, mintInfo.decimals),
  ]);
  const ctx: SolContext = { mint: mintInfo, holders, trade };

  const dims = [scoreSolSecurity(ctx), scoreSolMarket(ctx)];
  const fused = fuse(dims);
  const allSignals = dims.flatMap((d) => d.signals);
  const { summary, attestation } = await explain(fused.verdict, allSignals, tier, `SPL token ${mint} (solana)`);

  const freshness: Record<string, string> = {};
  for (const d of dims) freshness[d.key] = d.freshness;
  const dimensions = fused.dimensions as Partial<Record<DimensionKey, DimensionResult>>;

  const envelope: VerdictT = {
    subject: { type: "token", chain: "solana", address: mint, symbol: undefined, name: undefined },
    verdict: fused.verdict,
    score: fused.score,
    confidence: fused.confidence,
    summary,
    dimensions: dimensions as Record<DimensionKey, DimensionResult>,
    signals: allSignals,
    freshness,
    provenance: { simulation: tier === "flag" ? "NONE" : "SINGLE", cached_dimensions: [] },
    cost: { amount: COST[tier], currency: "USDT", tier },
    accuracy: { model_version: "v0.1.0", published_precision: null },
    ai_attestation: attestation,
    generated_at: new Date().toISOString(),
    latency_ms: Date.now() - started,
    disclaimer: "Informational only. Not financial advice.",
  };
  return Verdict.parse(envelope);
}
