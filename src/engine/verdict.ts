import { Verdict, type Verdict as VerdictT, type Signal, type DimensionResult, type DimensionKey } from "../types/verdict.js";
import type { ChainKey } from "../config.js";
import { scoreSecurity } from "./dimensions/security.js";
import { scoreMarket } from "./dimensions/market.js";
import { scoreTokenomics } from "./dimensions/tokenomics.js";
import { scoreSmartMoney } from "./dimensions/smartmoney.js";
import { fuse } from "./fuse.js";
import { explain } from "./explain.js";
import { gather, type RawContext as RawContextT } from "./context.js";
import { TIER_USD } from "../api/x402.js";
import type { HoneypotResult } from "../sim/honeypot.js";
import { cached } from "./cache.js";

// Short TTL so a pre-trade verdict is never meaningfully stale, but repeat/burst calls are instant.
const CACHE_TTL_MS = Number(process.env.VERITY_CACHE_TTL_MS ?? 60_000);

export type Tier = "flag" | "full" | "deep";

// Prices come from ONE source of truth (x402.ts) so the listed/charged price can never drift.
const COST: Record<Tier, { amount: string; currency: "USDT" }> = {
  flag: { amount: TIER_USD.flag, currency: "USDT" },
  full: { amount: TIER_USD.full, currency: "USDT" },
  deep: { amount: TIER_USD.deep, currency: "USDT" },
};

const MODEL_VERSION = "v0.1.0";

/**
 * Honest simulation provenance. "MULTI_VECTOR" is claimed ONLY when the on-fork multi-vector
 * simulation was DECISIVE — either it completed at least one real buy+sell round-trip, or it caught a
 * trap (honeypot / selective honeypot) by executing. A null sim, a missing venue, an Anvil failure,
 * or a run where nothing was even buyable is NOT proof and returns "NONE". This is what stops the
 * check layer from ever claiming "we actually bought AND sold" on a simulation that did not happen.
 */
export function simProvenance(sim: HoneypotResult | null | undefined): "MULTI_VECTOR" | "NONE" {
  if (!sim || !sim.simulated) return "NONE";
  const roundTrip = sim.vectors.some((v) => v.boughtOk && v.soldOk);
  const caughtTrap = sim.isHoneypot || sim.selectiveHoneypot;
  return roundTrip || caughtTrap ? "MULTI_VECTOR" : "NONE";
}

export type CoarseVerdict = {
  subject: VerdictT["subject"];
  verdict: VerdictT["verdict"];
  score: number;
  confidence: number;
  summary: string;
  tier: string;
  paid: false;
  note: string;
};

/**
 * A free/demo-safe projection of a verdict: the headline ONLY. It deliberately omits the paid
 * intelligence — signals, evidence, dimensions, simulation provenance, OKX metrics and the signed
 * receipt — so a free preview endpoint can never return the same result as the paid x402 endpoint
 * (which is a marketplace rejection cause). This is the TxSentinel/Argus "coarse READY vs paid
 * evidence" pattern.
 */
export function coarseVerdict(v: VerdictT): CoarseVerdict {
  return {
    subject: v.subject,
    verdict: v.verdict,
    score: v.score,
    confidence: v.confidence,
    summary: v.summary,
    tier: v.cost?.tier ?? "flag",
    paid: false,
    note: "Free preview — the full evidence, signals, simulation provenance and signed receipt are returned by the paid endpoint.",
  };
}

/**
 * The core product call: fused, evidence-linked pre-trade verdict for a token.
 * flag = static-only (fast, cheap). full = + multi-vector sim. deep = + committee report (later).
 */
export async function tokenVerdict(chain: ChainKey, address: string, tier: Tier = "full"): Promise<VerdictT> {
  return cached(`verdict:${chain}:${address.toLowerCase()}:${tier}`, CACHE_TTL_MS, async () => {
    const runSim = tier !== "flag";
    const ctx = await gather(chain, address, { sim: runSim });
    return buildVerdict(ctx, tier);
  });
}

/** Deep tier: verdict + committee research report, sharing one gathered context. */
export async function tokenVerdictDeep(chain: ChainKey, address: string): Promise<{ verdict: VerdictT; report: import("./report.js").CommitteeReport }> {
  return cached(`deep-report:${chain}:${address.toLowerCase()}`, CACHE_TTL_MS, async () => {
    const ctx = await gather(chain, address, { sim: true });
    const verdict = await buildVerdict(ctx, "deep");
    const { committeeReport } = await import("./report.js");
    const report = await committeeReport(ctx, verdict);
    return { verdict, report };
  });
}

/** Courtroom mode: verdict + Prosecutor-vs-Defense ruling (Creative Genius surface). */
export async function tokenVerdictCourtroom(chain: ChainKey, address: string): Promise<{ verdict: VerdictT; ruling: import("./courtroom.js").Ruling }> {
  const ctx = await gather(chain, address, { sim: true });
  const verdict = await buildVerdict(ctx, "deep");
  const { courtroom } = await import("./courtroom.js");
  const ruling = await courtroom(ctx, verdict);
  return { verdict, ruling };
}

/** Core verdict builder from an already-gathered context (pure-ish; only 0G explain does I/O). */
export async function buildVerdict(ctx: RawContextT, tier: Tier): Promise<VerdictT> {
  const started = Date.now();
  const { chain, address } = ctx;
  const dimensionScores = [scoreSecurity(ctx), scoreMarket(ctx), scoreTokenomics(ctx), scoreSmartMoney(ctx)];

  const fused = fuse(dimensionScores);
  const allSignals: Signal[] = dimensionScores.flatMap((d) => d.signals);
  const symbol = ctx.symbol;
  const name = ctx.name;

  const { summary, attestation } = await explain(fused.verdict, allSignals, tier, `${name ?? address} (${chain})`);

  const freshness: Record<string, string> = {};
  for (const d of dimensionScores) freshness[d.key] = d.freshness;

  const dimensions = fused.dimensions as Partial<Record<DimensionKey, DimensionResult>>;

  const envelope: VerdictT = {
    subject: { type: "token", chain, address, symbol, name },
    verdict: fused.verdict,
    score: fused.score,
    confidence: fused.confidence,
    summary,
    dimensions: dimensions as Record<DimensionKey, DimensionResult>,
    signals: allSignals,
    freshness,
    provenance: {
      simulation: simProvenance(ctx.sim),
      origins_tested: ctx.sim?.vectors?.length || undefined,
      cached_dimensions: [],
      replay: ctx.sim?.proof?.replay,
      fork_block: ctx.sim?.proof?.forkBlock,
    },
    cost: { ...COST[tier], tier },
    accuracy: { model_version: MODEL_VERSION, published_precision: null },
    ai_attestation: attestation, // TEE proof the AI reasoning ran unmodified (verifiable AI)
    okx_metrics: extractOkxMetrics(ctx), // live OKX Onchain OS data when configured
    generated_at: new Date().toISOString(),
    latency_ms: Date.now() - started,
    disclaimer: "Informational only. Not financial advice.",
  };

  // Runtime-validate against the Zod schema — the envelope contract is enforced, not assumed.
  return Verdict.parse(envelope);
}

/** Pull the headline OKX Onchain OS metrics onto the verdict for display (null if OKX not configured). */
function extractOkxMetrics(ctx: RawContextT): import("../types/verdict.js").OkxMetrics | null {
  if (!ctx.okx) return null;
  const { cluster, signals, advanced } = ctx.okx;
  const pct = (v: any): number | null => {
    if (v == null || v === "" || v === "--") return null;
    const n = typeof v === "string" ? parseFloat(v) : Number(v);
    if (Number.isNaN(n)) return null;
    return n > 1 ? n / 100 : n === 1 ? 0.01 : n; // 0-100 or 0-1 → 0-1; bare "1" is 1%, not 100% (safe)
  };
  const list: any[] = Array.isArray(signals) ? signals : Array.isArray(signals?.list) ? signals.list : [];
  return {
    smart_money_signals: list.length || null,
    cluster_concentration: cluster?.clusterConcentration ?? null,
    rug_pull_percent: pct(cluster?.rugPullPercent ?? cluster?.rugPullRatio),
    same_fund_source_percent: pct(cluster?.holderSameFundSourcePercent),
    dev_holding_percent: pct(advanced?.devHoldingPercent),
    bundle_holding_percent: pct(advanced?.bundleHoldingPercent),
  };
}
