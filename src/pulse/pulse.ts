import { fetchAllSources, type SourceResult, type Mention } from "./sources.js";
import { chatJson } from "../ai/router.js";
import { PulseVerdict, type PulseLabel } from "./types.js";

/**
 * Social Pulse — cross-platform sentiment verdict (Twitter + Reddit + YouTube) → HYPE / ORGANIC / DEAD.
 *
 * "DEAD" (almost no chatter) is decided deterministically by volume; HYPE-vs-ORGANIC is a judgment about
 * tone and coordination, made by a diverse model reading the actual mentions. Confidence scales with
 * how many sources responded, so a partial fetch is honestly labelled rather than silently overconfident.
 */

const DEAD_MENTION_THRESHOLD = 4; // fewer real mentions than this across all sources → DEAD

/** Pure volume assessment + confidence from source availability (unit-testable). */
export function assessVolume(sources: SourceResult[]): {
  totalMentions: number; sourcesOk: number; totalEngagement: number; deadByVolume: boolean; confidence: number;
} {
  const ok = sources.filter((s) => s.status === "ok");
  const totalMentions = ok.reduce((n, s) => n + s.mentions.length, 0);
  const totalEngagement = ok.reduce((n, s) => n + s.mentions.reduce((e, m) => e + (m.engagement || 0), 0), 0);
  // confidence: 3 live sources → 0.9, 2 → 0.7, 1 → 0.5, 0 → 0.15
  const confidence = ok.length >= 3 ? 0.9 : ok.length === 2 ? 0.7 : ok.length === 1 ? 0.5 : 0.15;
  return { totalMentions, sourcesOk: ok.length, totalEngagement, deadByVolume: totalMentions < DEAD_MENTION_THRESHOLD, confidence };
}

/** buzz score 0..100 — VOLUME-led (how many distinct people are posting) with a modest engagement bonus.
 * Volume drives it because a single viral video's view-count shouldn't make a quiet token look loud. */
export function buzzScore(totalMentions: number, totalEngagement: number): number {
  const vol = Math.min(72, totalMentions * 4); // ~18 mentions → 72 (needs real breadth of chatter)
  const eng = totalEngagement > 0 ? Math.min(28, Math.log10(1 + totalEngagement) * 4.5) : 0; // modest, log-compressed
  return Math.round(vol + eng);
}

export async function socialPulse(query: string): Promise<PulseVerdict> {
  const observed_at = new Date().toISOString();
  const sources = await fetchAllSources(query);
  const { totalMentions, sourcesOk, totalEngagement, deadByVolume, confidence } = assessVolume(sources);

  const sourceRows = sources.map((s) => ({
    source: s.source, status: s.status, count: s.mentions.length,
    engagement: s.mentions.reduce((e, m) => e + (m.engagement || 0), 0), message: s.message,
  }));
  const allMentions: Mention[] = sources.flatMap((s) => s.mentions);
  const sample = [...allMentions].sort((a, b) => b.engagement - a.engagement).slice(0, 8)
    .map((m) => ({ source: m.source, text: m.text, engagement: m.engagement, url: m.url }));
  const buzz = buzzScore(totalMentions, totalEngagement);

  const base = {
    ok: true, query, observed_at,
    sources: sourceRows, total_mentions: totalMentions, sources_ok: sourcesOk,
    buzz_score: buzz, confidence, sample,
    disclaimer: "Social signal only. Chatter is not price prediction; hype is often a sell signal.",
  };

  if (sourcesOk === 0) {
    return PulseVerdict.parse({ ...base, ok: false, label: "DEAD", sentiment: "neutral", rationale: "No social source responded — cannot assess.", red_flags: [], confidence: 0.15, error: sources.map((s) => `${s.source}: ${s.message}`).join("; ") });
  }
  if (deadByVolume) {
    return PulseVerdict.parse({ ...base, label: "DEAD", sentiment: "neutral", rationale: `Only ${totalMentions} mention(s) found across ${sourcesOk} live source(s) — effectively no organic chatter.`, red_flags: [] });
  }

  // HYPE vs ORGANIC + sentiment — judged by a model over the real mentions (chatJson: robust parse + retry)
  const feed = allMentions.slice(0, 30).map((m) => `[${m.source} · ${m.engagement} eng] ${m.text}`).join("\n");
  try {
    const { data } = await chatJson<{ label: string; sentiment: string; rationale: string; red_flags: string[] }>(
      [
        { role: "system", content: `You analyze crypto social chatter about a SPECIFIC topic. Classify OVERALL as one of: HYPE (loud, promotional, coordinated shilling, repetitive "to the moon"/price-prediction spam that IS genuinely about the topic), ORGANIC (genuine mixed discussion, real questions/critique/news about the topic), or DEAD (barely any real conversation about the topic). CRITICAL: if the posts are mostly generic spam, giveaways, mass-tag bot lists, or wallet-begging that are NOT actually about this specific topic, classify as DEAD — irrelevant spam is not real chatter. Also give sentiment (bullish|bearish|neutral|mixed), a rationale of AT MOST 25 words grounded in the posts, and up to 4 short red_flags ([] if none). Use ONLY the provided posts. Return ONLY compact JSON {"label","sentiment","rationale","red_flags":[]} and nothing else.` },
        { role: "user", content: `Topic: ${query}\n${sourcesOk} of 3 sources live, ${totalMentions} mentions.\n\nPOSTS:\n${feed}` },
      ],
      { tier: "strong", maxTokens: 500, temperature: 0.2 }
    );
    const label = (["HYPE", "ORGANIC", "DEAD"].includes(data.label) ? data.label : "ORGANIC") as PulseLabel;
    const sentiment = (["bullish", "bearish", "neutral", "mixed"].includes(data.sentiment) ? data.sentiment : "mixed");
    return PulseVerdict.parse({
      ...base, label, sentiment,
      // if the classifier judged DEAD (chatter was spam/irrelevant), the raw volume was fake → reflect that
      buzz_score: label === "DEAD" ? Math.min(base.buzz_score, 15) : base.buzz_score,
      rationale: String(data.rationale ?? "").slice(0, 300) || `${totalMentions} mentions across ${sourcesOk} sources.`,
      red_flags: Array.isArray(data.red_flags) ? data.red_flags.slice(0, 5).map(String) : [],
    });
  } catch {
    // deterministic fallback if the model is unreachable: label by buzz density
    const label: PulseLabel = buzz >= 75 ? "HYPE" : "ORGANIC";
    return PulseVerdict.parse({ ...base, label, sentiment: "neutral", rationale: `${totalMentions} mentions, buzz ${buzz}/100 (classifier unavailable — volume-based label).`, red_flags: [] });
  }
}
