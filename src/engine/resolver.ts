import type { ChainKey } from "../config.js";
import type { VerdictLabel } from "../types/verdict.js";
import { getMarket } from "../adapters/dexscreener.js";
import { simulateHoneypot } from "../sim/honeypot.js";
import { gradeVerdict, isAttestConfigured } from "../attest/registry.js";
import type { Hex } from "viem";

/**
 * Accuracy resolver — "did it actually rug?". This is what closes Aletheia's on-chain accuracy loop:
 * a verdict is committed BEFORE the outcome is known, then this module measures the real outcome later
 * and grades the call. No incumbent grades itself; this is the proof behind "audit me, don't trust me".
 *
 * Outcome is measured from ground truth: current liquidity vs the baseline captured at verdict time,
 * plus a fresh honeypot re-simulation (a token that became unsellable is a rug even if liquidity lingers).
 * The grading truth-table is pure and unit-tested; only the measurement does I/O.
 */

export type Outcome = "RUGGED" | "HONEYPOT_FLIP" | "DEGRADED" | "SURVIVED" | "INCONCLUSIVE";

export type ResolvedOutcome = {
  ok: boolean;
  observed_at: string;
  chain: ChainKey;
  address: string;
  outcome: Outcome;
  rugged: boolean;
  liquidityBaselineUsd: number | null;
  liquidityNowUsd: number;
  liquidityDropPct: number | null; // 0..1, null if no baseline
  nowHoneypot: boolean;
  evidence: string[];
  error?: string;
};

/** Pure grader: was the original verdict correct given the realized outcome? (unit-testable) */
export function gradeOutcome(original: VerdictLabel, outcome: Outcome): { correct: boolean | null; rationale: string } {
  const bad = outcome === "RUGGED" || outcome === "HONEYPOT_FLIP" || outcome === "DEGRADED";
  if (outcome === "INCONCLUSIVE") return { correct: null, rationale: "Outcome not yet determinable — not graded." };
  if (bad) {
    if (original === "GO") return { correct: false, rationale: `Called GO but the token ${outcome === "DEGRADED" ? "lost most liquidity" : "rugged"} — false negative.` };
    return { correct: true, rationale: `Warned (${original}) and the token ${outcome.toLowerCase().replace("_", " ")} — correct call.` };
  }
  // SURVIVED
  if (original === "AVOID") return { correct: false, rationale: "Called AVOID but the token survived and stayed tradeable — false positive." };
  return { correct: true, rationale: `Called ${original} and the token survived — correct call.` };
}

/** Classify the realized outcome from measured liquidity + honeypot state (pure, testable). */
export function classifyOutcome(input: {
  liquidityBaselineUsd: number | null;
  liquidityNowUsd: number;
  nowHoneypot: boolean;
}): { outcome: Outcome; rugged: boolean; liquidityDropPct: number | null; evidence: string[] } {
  const { liquidityBaselineUsd: base, liquidityNowUsd: now, nowHoneypot } = input;
  const evidence: string[] = [];
  const drop = base && base > 0 ? Math.max(0, 1 - now / base) : null;

  if (nowHoneypot) {
    evidence.push("fresh simulation: token is now unsellable (honeypot)");
    return { outcome: "HONEYPOT_FLIP", rugged: true, liquidityDropPct: drop, evidence };
  }
  if (base != null && base > 0) {
    evidence.push(`liquidity ${base.toFixed(0)} → ${now.toFixed(0)} USD (−${((drop ?? 0) * 100).toFixed(0)}%)`);
    if ((drop ?? 0) >= 0.9 || now < 2_000) return { outcome: "RUGGED", rugged: true, liquidityDropPct: drop, evidence };
    if ((drop ?? 0) >= 0.5) return { outcome: "DEGRADED", rugged: false, liquidityDropPct: drop, evidence };
    return { outcome: "SURVIVED", rugged: false, liquidityDropPct: drop, evidence };
  }
  // no baseline — fall back to absolute thresholds, lower confidence
  if (now < 2_000) { evidence.push(`current liquidity only $${now.toFixed(0)} — effectively pulled`); return { outcome: "RUGGED", rugged: true, liquidityDropPct: null, evidence }; }
  if (now >= 20_000) { evidence.push(`healthy current liquidity $${now.toFixed(0)}`); return { outcome: "SURVIVED", rugged: false, liquidityDropPct: null, evidence }; }
  evidence.push(`liquidity $${now.toFixed(0)} and no baseline — inconclusive`);
  return { outcome: "INCONCLUSIVE", rugged: false, liquidityDropPct: null, evidence };
}

/** Measure the real outcome of a token now, optionally against a baseline liquidity captured at verdict time. */
export async function resolveOutcome(
  chain: ChainKey,
  address: string,
  opts: { baselineLiquidityUsd?: number | null } = {}
): Promise<ResolvedOutcome> {
  const observed_at = new Date().toISOString();
  const addr = address.toLowerCase() as `0x${string}`;
  try {
    const [market, sim] = await Promise.all([
      getMarket(chain, address),
      simulateHoneypot(chain, addr).catch(() => null),
    ]);
    const liquidityNowUsd = market.totalLiquidityUsd;
    const nowHoneypot = !!(sim?.simulated && (sim.isHoneypot || sim.selectiveHoneypot));
    const { outcome, rugged, liquidityDropPct, evidence } = classifyOutcome({
      liquidityBaselineUsd: opts.baselineLiquidityUsd ?? null,
      liquidityNowUsd,
      nowHoneypot,
    });
    return {
      ok: true, observed_at, chain, address: addr, outcome, rugged,
      liquidityBaselineUsd: opts.baselineLiquidityUsd ?? null,
      liquidityNowUsd, liquidityDropPct, nowHoneypot, evidence,
    };
  } catch (e: any) {
    return {
      ok: false, observed_at, chain, address: addr, outcome: "INCONCLUSIVE", rugged: false,
      liquidityBaselineUsd: opts.baselineLiquidityUsd ?? null, liquidityNowUsd: 0, liquidityDropPct: null,
      nowHoneypot: false, evidence: [], error: e?.message ?? String(e),
    };
  }
}

/** Full loop: resolve the outcome, grade the original verdict, and (if configured + id given) record the grade on-chain. */
export async function resolveAndGrade(
  chain: ChainKey,
  address: string,
  original: VerdictLabel,
  opts: { baselineLiquidityUsd?: number | null; verdictId?: Hex } = {}
): Promise<{ resolved: ResolvedOutcome; correct: boolean | null; rationale: string; gradeTx?: string | null }> {
  const resolved = await resolveOutcome(chain, address, { baselineLiquidityUsd: opts.baselineLiquidityUsd });
  const { correct, rationale } = gradeOutcome(original, resolved.outcome);
  let gradeTx: string | null | undefined;
  if (correct != null && opts.verdictId && isAttestConfigured()) {
    gradeTx = await gradeVerdict(opts.verdictId, correct).catch(() => null);
  }
  return { resolved, correct, rationale, gradeTx };
}
