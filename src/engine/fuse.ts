import type { DimensionScore, DimensionKey, VerdictLabel, DimensionResult } from "../types/verdict.js";

/** Default cross-dimension weights (normalized over whichever dimensions are present). */
export const DEFAULT_WEIGHTS: Record<DimensionKey, number> = {
  security: 0.35,
  market_structure: 0.15,
  smart_money: 0.15,
  tokenomics: 0.1,
  social_narrative: 0.1,
  research: 0.15,
};

export type Fused = {
  verdict: VerdictLabel;
  score: number;
  confidence: number;
  dimensions: Partial<Record<DimensionKey, DimensionResult>>;
  hardFlag: boolean;
};

export function fuse(scores: DimensionScore[]): Fused {
  const present = scores.filter((s) => s.confidence > 0);
  const totalW = present.reduce((sum, s) => sum + DEFAULT_WEIGHTS[s.key], 0) || 1;

  let composite = 0;
  let confAcc = 0;
  const dimensions: Partial<Record<DimensionKey, DimensionResult>> = {};

  for (const s of present) {
    const w = DEFAULT_WEIGHTS[s.key] / totalW;
    composite += s.score * w;
    confAcc += s.confidence * w;
    dimensions[s.key] = {
      verdict: s.verdict,
      score: Math.round(s.score),
      weight: Number(w.toFixed(3)),
      confidence: Number(s.confidence.toFixed(3)),
      summary: s.summary,
    };
  }

  let score = Math.round(composite);
  const hardFlag = scores.some((s) => s.signals.some((sig) => sig.is_hard_flag));

  // Verdict mapping — hard flag in any dimension caps the whole verdict.
  let verdict: VerdictLabel = score >= 75 ? "GO" : score >= 45 ? "CAUTION" : "AVOID";
  if (hardFlag) {
    verdict = "AVOID";
    score = Math.min(score, 15);
  }

  // Confidence calibration: base on weighted dimension confidence, penalize thin coverage.
  // Denominator = dimensions the pipeline actually ATTEMPTED (scores), not the full weight table —
  // two weight keys (social_narrative, research) are never produced and would falsely cap coverage.
  const coverage = present.length / Math.max(1, scores.length); // 0..1
  let confidence = confAcc * (0.6 + 0.4 * coverage);
  // low confidence must never present as a confident GO
  if (verdict === "GO" && confidence < 0.5) verdict = "CAUTION";
  confidence = Number(Math.max(0, Math.min(1, confidence)).toFixed(3));

  return { verdict, score, confidence, dimensions, hardFlag };
}
