import { getScraper } from "../pulse/sources.js";
import { juryConsensus } from "../ai/router.js";

/**
 * KOL / analyst trust check — "is this X account a real, credible voice, or a bot/shill?"
 *
 * Deterministic signals from the profile (account age, follower/following ratio, engagement vs
 * follower count, tweet-rate, verification, repetition in recent posts) produce a 0–100 base score;
 * a diverse jury then reads the actual recent tweets and votes TRUSTED / MIXED / LIKELY_BOT. Honest:
 * this scores credibility signals, not truth of any specific claim.
 */

export type KolResult = {
  ok: boolean;
  observed_at: string;
  handle: string;
  followers: number;
  following: number;
  account_age_days: number | null;
  verified: boolean;
  trust_score: number; // 0–100
  verdict: "TRUSTED" | "MIXED" | "LIKELY_BOT" | "UNAVAILABLE";
  red_flags: string[];
  narration: string;
  jury?: unknown;
  error?: string;
};

function ageDays(joined: any): number | null {
  try { const t = joined instanceof Date ? joined.getTime() : new Date(joined).getTime(); return t ? Math.max(0, Math.round((Date.now() - t) / 86_400_000)) : null; } catch { return null; }
}

export async function checkKol(rawHandle: string): Promise<KolResult> {
  const observed_at = new Date().toISOString();
  const handle = String(rawHandle || "").replace(/^@/, "").replace(/[^A-Za-z0-9_]/g, "").slice(0, 30);
  const base: KolResult = { ok: false, observed_at, handle, followers: 0, following: 0, account_age_days: null, verified: false, trust_score: 0, verdict: "UNAVAILABLE", red_flags: [], narration: "", };
  if (!handle) return { ...base, error: "handle required" };
  const scraper = await getScraper();
  if (!scraper) return { ...base, error: "twitter not configured", narration: "Cannot assess — the social data source is unavailable." };

  let profile: any;
  try { profile = await scraper.getProfile(handle); } catch (e: any) { return { ...base, error: `profile fetch failed: ${e?.message ?? e}`, narration: `Could not find @${handle}.` }; }
  const followers = Number(profile?.followersCount) || 0;
  const following = Number(profile?.followingCount) || 0;
  const tweets = Number(profile?.tweetsCount) || 0;
  const verified = Boolean(profile?.isVerified || profile?.isBlueVerified);
  const age = ageDays(profile?.joined);

  // recent tweets for engagement + repetition + jury
  const recent: any[] = [];
  try { for await (const t of scraper.getTweets(handle, 15)) { recent.push(t); if (recent.length >= 15) break; } } catch { /* tolerate */ }
  const eng = recent.map((t) => (Number(t.likes) || 0) + (Number(t.retweets) || 0));
  const avgEng = eng.length ? eng.reduce((a, b) => a + b, 0) / eng.length : 0;
  const texts = recent.map((t) => String(t.text || "").slice(0, 120).toLowerCase().trim()).filter(Boolean);
  const dupRate = texts.length ? 1 - new Set(texts).size / texts.length : 0; // share of repeated posts
  const engRatio = followers > 0 ? avgEng / followers : 0; // bought/bot followers → ~0

  // deterministic score
  let score = 50;
  const flags: string[] = [];
  if (verified) score += 12;
  if (age !== null) { if (age < 60) { score -= 20; flags.push(`account only ${age}d old`); } else if (age > 730) score += 8; }
  if (followers >= 10_000) score += 8; else if (followers < 300) { score -= 8; flags.push("very small audience"); }
  if (following > 0 && followers / Math.max(1, following) < 0.5 && followers < 5000) { score -= 8; flags.push("follows far more than follow it"); }
  // Low engagement-per-follower only reads as "bought/bot audience" for SMALL/mid accounts. High-profile
  // accounts (celebrity founders, exchange/dev leads, media) accumulate millions of passive followers, so
  // their ratio is structurally low — flagging that as "bot" contradicts the jury's read of genuine posts.
  // We also only score the ratio when we actually fetched engagement data (avgEng 0 = no data, not "zero").
  if (followers >= 2000 && followers < 100_000 && avgEng > 0 && engRatio < 0.0005) { score -= 22; flags.push("near-zero engagement vs follower count (bought/bot audience)"); }
  else if (engRatio > 0.01) score += 8;
  if (dupRate > 0.3) { score -= 20; flags.push("posts the same content on repeat (bot pattern)"); }
  if (age !== null && age > 0 && tweets / Math.max(1, age) > 40) { score -= 12; flags.push("extreme tweet rate (spam/automation)"); }

  // jury reads the actual recent posts
  let juryOut: any = undefined;
  if (recent.length) {
    const feed = recent.slice(0, 8).map((t) => `[${(Number(t.likes) || 0)}❤] ${String(t.text || "").slice(0, 160)}`).join("\n");
    juryOut = await juryConsensus(
      "You judge whether an X (Twitter) crypto account is a credible real voice or a bot/coordinated shill. Consider originality, whether posts read like genuine analysis vs repetitive promotion/spam, and coherence. Cite a specific observation.",
      `@${handle} — ${followers} followers, ${following} following, ${verified ? "verified" : "unverified"}, ${age ?? "?"}d old, avg engagement ${Math.round(avgEng)}.\nRecent posts:\n${feed}`,
      ["TRUSTED", "MIXED", "LIKELY_BOT"],
    ).catch(() => undefined);
    if (juryOut) {
      if (juryOut.label === "LIKELY_BOT") score -= 18 * juryOut.agreement;
      else if (juryOut.label === "TRUSTED") score += 12 * juryOut.agreement;
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const verdict: KolResult["verdict"] = score >= 65 ? "TRUSTED" : score >= 40 ? "MIXED" : "LIKELY_BOT";
  // The jury's read of the actual posts is an assessment, not a red flag — keep red_flags for genuine
  // negatives only, surface the jury read separately, and strip a trailing period so we never end in "..".
  const juryNote = juryOut?.votes?.[0]?.reason ? String(juryOut.votes[0].reason).replace(/[.\s]+$/, "") : "";
  const flagPart = flags.length ? `. Red flags: ${flags.slice(0, 3).join("; ")}` : "";
  const juryPart = juryNote ? `. Jury read: ${juryNote}` : "";
  const narration = `@${handle} scores ${score}/100 — ${verdict === "TRUSTED" ? "a credible voice" : verdict === "MIXED" ? "mixed signals, verify claims" : "likely a bot or paid shill"}. ${followers.toLocaleString()} followers, ${age ?? "?"}d old${flagPart}${juryPart}.`;
  return { ok: true, observed_at, handle, followers, following, account_age_days: age, verified, trust_score: score, verdict, red_flags: flags, narration, jury: juryOut };
}
