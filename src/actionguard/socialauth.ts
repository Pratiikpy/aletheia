import { socialPulse } from "../pulse/pulse.js";

/**
 * Social-hype authenticity — "is the buzz around this token real, or manufactured shilling?"
 *
 * Rides Social Pulse (live Twitter + Reddit via Agent Reach), which already separates HYPE
 * (loud, promotional, coordinated) from ORGANIC (genuine discussion) from DEAD. We reframe it into a
 * single 0–100 authenticity score + a rug-social verdict, so an agent can flag manufactured euphoria
 * before it buys. Honest: social signal only — high authenticity is not a buy signal.
 */

export type SocialAuthResult = {
  ok: boolean;
  observed_at: string;
  query: string;
  authenticity_score: number; // 0–100 (higher = more genuine)
  verdict: "ORGANIC" | "MANUFACTURED_HYPE" | "NO_SIGNAL";
  buzz_score: number;
  sentiment: string;
  total_mentions: number;
  red_flags: string[];
  narration: string;
  sample: unknown[];
  disclaimer: string;
};

export async function socialAuthenticity(query: string): Promise<SocialAuthResult> {
  const observed_at = new Date().toISOString();
  const p: any = await socialPulse(query);
  const conf = Number(p.confidence) || 0.3;
  let score: number, verdict: SocialAuthResult["verdict"];

  if (!p.ok || p.label === "DEAD") {
    score = Math.round(20 * conf);
    verdict = "NO_SIGNAL";
  } else if (p.label === "HYPE") {
    // loud + promotional + coordinated = manufactured until proven otherwise
    score = Math.round(35 - 15 * conf); // more confident HYPE → lower authenticity
    verdict = "MANUFACTURED_HYPE";
  } else {
    // ORGANIC: genuine discussion
    score = Math.round(60 + 25 * conf);
    verdict = "ORGANIC";
  }
  score = Math.max(0, Math.min(100, score));

  const red_flags: string[] = Array.isArray(p.red_flags) ? [...p.red_flags] : [];
  if (verdict === "MANUFACTURED_HYPE") red_flags.unshift("coordinated / promotional hype pattern");
  const mentions = Number(p.total_mentions) || 0;
  const narration =
    verdict === "MANUFACTURED_HYPE" ? `Buzz around "${query}" looks manufactured (authenticity ${score}/100): loud, promotional, coordinated. Treat the hype as a sell signal, not a buy one.`
    : verdict === "ORGANIC" ? `Buzz around "${query}" reads organic (authenticity ${score}/100): genuine mixed discussion, not just shilling.`
    : mentions >= 5 ? `Chatter on "${query}" is thin or low-quality (${mentions} mentions, authenticity ${score}/100) — mostly off-topic or noise, no reliable signal to act on.`
    : `Barely any real chatter on "${query}" (authenticity ${score}/100) — no social signal to act on.`;

  return {
    ok: true, observed_at, query, authenticity_score: score, verdict,
    buzz_score: Number(p.buzz_score) || 0, sentiment: p.sentiment ?? "neutral",
    total_mentions: Number(p.total_mentions) || 0, red_flags, narration,
    sample: (p.sample ?? []).slice(0, 5),
    disclaimer: "Social signal only. Authenticity measures whether chatter is genuine, not whether the token is a good buy.",
  };
}
