import type { Signal, VerdictLabel, AiAttestation } from "../types/verdict.js";
import { chat } from "../ai/router.js";

export type ExplainResult = { summary: string; attestation: AiAttestation | null };

/**
 * Plain-English summary. Grounded: the model may ONLY use the provided findings — no invention.
 * flag tier → deterministic (fast, no LLM dependency). full/deep → 0G decentralized compute.
 */
export async function explain(
  verdict: VerdictLabel,
  signals: Signal[],
  tier: "flag" | "full" | "deep",
  subjectLabel: string
): Promise<ExplainResult> {
  const notable = [...signals].sort((a, b) => b.severity - a.severity);
  const deterministic = deterministicSummary(verdict, notable);

  if (tier === "flag" || notable.length === 0) return { summary: deterministic, attestation: null };

  try {
    const findings = notable.slice(0, 8).map((s, i) => `${i + 1}. [severity ${s.severity}/5] ${s.finding}`).join("\n");
    // "strong" tier = a 0G decentralized-compute model (TEE-backed infra; no per-call proof on the router path).
    const { content, teeVerified, provider, model } = await chat(
      [
        { role: "system", content: "You write a 1-2 sentence plain-English pre-trade risk summary for a trader. Use ONLY the findings provided — never invent facts, numbers, or claims not present. Be direct and specific. No hedging boilerplate, no disclaimers." },
        { role: "user", content: `Subject: ${subjectLabel}\nOverall verdict: ${verdict}\nFindings:\n${findings}\n\nWrite the summary.` },
      ],
      { tier: "strong", maxTokens: 700, temperature: 0.2, timeoutMs: 30_000, verifyTee: true }
    );
    const clean = content.trim();
    // A reasoning-tier model can spend its budget on hidden reasoning and return a content string cut
    // off mid-sentence. Only trust the LLM summary when it is substantial AND ends on real sentence
    // punctuation; otherwise fall back to the clean deterministic template rather than ship a fragment.
    const complete = clean.length > 20 && /[.!?]["')”]?$/.test(clean);
    return { summary: complete ? clean : deterministic, attestation: { tee_verified: !!teeVerified, provider, model } };
  } catch {
    return { summary: deterministic, attestation: null }; // reliability: never fail the verdict on an LLM hiccup
  }
}

function deterministicSummary(verdict: VerdictLabel, notable: Signal[]): string {
  if (notable.length === 0) return "No red flags detected across simulation and static analysis.";
  const hard = notable.filter((s) => s.is_hard_flag);
  const lead = hard.length ? "Critical risk. " : verdict === "AVOID" ? "High risk. " : verdict === "CAUTION" ? "Proceed carefully. " : "";
  return lead + notable.slice(0, 3).map((s) => s.finding).join(" ");
}
