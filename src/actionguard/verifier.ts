import { jury } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";

/**
 * AI Output Verifier (Mira-style) — before an agent trusts another agent's answer, cross-check it with
 * MULTIPLE independent 0G models. Each model rates the answer's correctness for the question and flags
 * unsupported/false claims; we aggregate into a confidence + agreement read. High mean + low disagreement
 * = VERIFIED; high disagreement = DISPUTED; low mean = LIKELY_WRONG. Per-call ASP, no external data moat.
 */

export type OutputVerification = {
  ok: boolean;
  observed_at: string;
  verdict: "VERIFIED" | "DISPUTED" | "LIKELY_WRONG" | "INSUFFICIENT";
  confidence: number; // 0..1
  mean_score: number; // 0..100 average correctness across models
  agreement: number; // 0..1 (1 = models agree)
  flagged_claims: string[]; // union of unsupported/false claims the models raised
  models: { model: string; score: number | null }[];
  summary: string;
  signed?: SignedReceipt | null;
  error?: string;
};

function parseJson(s: string): any | undefined {
  const t = (s || "").trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
  try { return JSON.parse(t); } catch {}
  const a = t.indexOf("{"), b = t.lastIndexOf("}");
  if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch {} }
  return undefined;
}

/** Aggregate per-model scores into a verdict (pure, testable). */
export function aggregateVerification(scores: number[]): { verdict: OutputVerification["verdict"]; confidence: number; mean: number; agreement: number } {
  // one model's opinion is not cross-model consensus — need ≥2 to claim VERIFIED/agreement.
  if (scores.length < 2) return { verdict: "INSUFFICIENT", confidence: 0.15, mean: Math.round(scores[0] ?? 0), agreement: 0 };
  const mean = scores.reduce((s, x) => s + x, 0) / scores.length;
  const variance = scores.reduce((s, x) => s + (x - mean) ** 2, 0) / scores.length;
  const std = Math.sqrt(variance);
  const agreement = Math.max(0, 1 - std / 50); // std of 50 → 0 agreement
  let verdict: OutputVerification["verdict"];
  if (agreement < 0.5) verdict = "DISPUTED";
  else if (mean >= 70) verdict = "VERIFIED";
  else if (mean < 45) verdict = "LIKELY_WRONG";
  else verdict = "DISPUTED";
  // confidence: high when models agree AND lean decisive
  const confidence = Math.min(0.95, agreement * (0.5 + Math.abs(mean - 50) / 100));
  return { verdict, confidence: Number(confidence.toFixed(2)), mean: Math.round(mean), agreement: Number(agreement.toFixed(2)) };
}

export async function verifyOutput(question: string, answer: string): Promise<OutputVerification> {
  const observed_at = new Date().toISOString();
  try {
    const results = await jury(
      [
        { role: "system", content: "You are an independent fact-checker. Given a QUESTION and an ANSWER, judge ONLY whether the answer is correct and well-supported. Return ONLY JSON {\"score\": 0-100 (correctness), \"unsupported_claims\": [short strings]}. Be strict: score low if the answer is wrong, fabricated, or unsupported." },
        { role: "user", content: `QUESTION: ${question}\n\nANSWER: ${answer}` },
      ],
      ["strong", "alt", "reasoning"],
      { temperature: 0.1, maxTokens: 400 }
    );
    const models: { model: string; score: number | null }[] = [];
    const scores: number[] = [];
    const flagged = new Set<string>();
    for (const r of results) {
      const d = parseJson(r.content);
      const score = d && typeof d.score === "number" ? Math.max(0, Math.min(100, d.score)) : null;
      models.push({ model: r.model, score });
      if (score != null) scores.push(score);
      if (Array.isArray(d?.unsupported_claims)) for (const c of d.unsupported_claims.slice(0, 5)) flagged.add(String(c).slice(0, 160));
    }
    const { verdict, confidence, mean, agreement } = aggregateVerification(scores);
    const summary =
      verdict === "VERIFIED" ? `${models.length} independent models agree the answer is correct (avg ${mean}/100).` :
      verdict === "LIKELY_WRONG" ? `Models judge the answer incorrect/unsupported (avg ${mean}/100).` :
      verdict === "DISPUTED" ? `Models disagree on this answer (avg ${mean}/100, agreement ${(agreement * 100).toFixed(0)}%) — treat as unverified.` :
      "Not enough model responses to verify.";
    const signed = await signReceipt({ kind: "proof_of_work", question: String(question).slice(0, 400), answer: String(answer).slice(0, 400), verdict, mean_score: mean, agreement, observed_at });
    return { ok: true, observed_at, verdict, confidence, mean_score: mean, agreement, flagged_claims: [...flagged].slice(0, 8), models, summary, signed };
  } catch (e: any) {
    return { ok: false, observed_at, verdict: "INSUFFICIENT", confidence: 0.1, mean_score: 0, agreement: 0, flagged_claims: [], models: [], summary: "Verification failed.", error: e?.message ?? String(e) };
  }
}
