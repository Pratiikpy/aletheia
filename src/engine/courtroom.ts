import type { RawContext } from "./context.js";
import type { Verdict } from "../types/verdict.js";
import { chat } from "../ai/router.js";

/**
 * The Aletheia Courtroom (Creative Genius surface): a Prosecutor and a Defense argue the token from the
 * SAME evidence (independent 0G models), then Aletheia presides and issues a ruling + sentence.
 * Adversarial theater around a rigorous verdict — screenshot-friendly, agent-hires-agent themed.
 */

export type Ruling = {
  verdict: Verdict["verdict"];
  sentence: string; // one-line "sentence" (the memorable ruling)
  prosecution: string;
  defense: string;
  ruling: string; // Aletheia's reasoning
  models: { prosecutor: string; defense: string };
  generated_at: string;
};

function evidenceSheet(ctx: RawContext, v: Verdict): string {
  const lines = [`Defendant: ${ctx.name ?? v.subject.address} (${ctx.symbol ?? "?"}) on ${ctx.chain}`, `Aletheia verdict: ${v.verdict} ${v.score}/100 (confidence ${(v.confidence * 100).toFixed(0)}%)`, `Established/CEX: ${ctx.established}`, "Evidence on record:"];
  for (const s of v.signals) lines.push(`  - [sev ${s.severity}/5${s.is_hard_flag ? ", CRITICAL" : ""}] ${s.finding}`);
  if (!v.signals.length) lines.push("  - (no red flags found across simulation and analysis)");
  return lines.join("\n");
}

const RULES = "This is a pre-trade risk courtroom. Use ONLY the evidence on record — never invent facts. Stay in character, be sharp and concise (3-4 sentences).";

export async function courtroom(ctx: RawContext, v: Verdict): Promise<Ruling> {
  const sheet = evidenceSheet(ctx, v);
  const [pros, def] = await Promise.all([
    chat([{ role: "system", content: RULES + " You are the PROSECUTOR. Argue that this token is dangerous / a likely rug, citing the strongest evidence. If the evidence is weak, concede honestly." }, { role: "user", content: sheet }], { tier: "strong", maxTokens: 500, temperature: 0.35 }).catch(() => ({ content: "The prosecution rests without sufficient evidence.", model: "n/a" })),
    chat([{ role: "system", content: RULES + " You are the DEFENSE. Steelman the token / argue it is safe to trade, citing mitigating evidence. If it is indefensible, concede honestly." }, { role: "user", content: sheet }], { tier: "alt", maxTokens: 500, temperature: 0.35 }).catch(() => ({ content: "The defense concedes.", model: "n/a" })),
  ]);

  // The model can return an empty (non-throwing) response; the .catch above only handles throws, so
  // guard blank content with a deterministic, verdict-consistent fallback so a side is never missing.
  const prosecution = pros.content?.trim() ||
    (v.verdict === "AVOID" ? "The prosecution rests on the record: the flagged critical risks speak for themselves."
      : "The prosecution concedes it cannot prove intent to defraud on this evidence, but notes the risks on record.");
  const defense = def.content?.trim() ||
    (v.verdict === "AVOID" ? "The defense cannot in good conscience argue this token is safe given the evidence on record."
      : "The defense rests on the clean record: no honeypot, no critical authority, and a functioning two-way market.");

  const { content: rulingText } = await chat(
    [
      { role: "system", content: RULES + ` You are JUDGE ALETHEIA delivering the ruling. Output ONLY the ruling itself — do NOT restate these instructions, your role, or your thought process. Write exactly 2-3 sentences of reasoning consistent with the ${v.verdict} verdict, then a final line starting with "SENTENCE:" giving one memorable one-line ruling (e.g. "SENTENCE: GUILTY of being an unsellable honeypot — do not trade.").` },
      { role: "user", content: `${sheet}\n\nPROSECUTION:\n${prosecution}\n\nDEFENSE:\n${defense}\n\nDeliver your ruling now.` },
    ],
    { tier: "strong", maxTokens: 400, temperature: 0.25 }
  ).catch(() => ({ content: "SENTENCE: " + v.summary }));

  const m = rulingText?.match(/SENTENCE:\s*(.+?)$/im);
  const sentence = (m?.[1] ?? v.summary).trim();
  let ruling = rulingText?.replace(/SENTENCE:[\s\S]*/i, "").trim() || v.summary;
  // guard against a model that leaks its meta-reasoning instead of ruling → fall back to the summary
  if (/\b(I am JUDGE|I must|I need to|I should|these instructions|one-line ruling)\b/i.test(ruling)) ruling = v.summary;

  return { verdict: v.verdict, sentence, prosecution, defense, ruling, models: { prosecutor: pros.model, defense: def.model }, generated_at: new Date().toISOString() };
}
