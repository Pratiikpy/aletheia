import type { ChainKey } from "../config.js";
import * as okx from "../adapters/okx.js";

/**
 * Trench scanner — pre-buy due diligence for a fresh launch (pump.fun-style). Reads OKX Onchain OS
 * memepump data: how much supply the dev holds, how much was bought in bundled launch txns, sniper/aped
 * ratio, and the dev's prior-rug history. Returns SAFE_LAUNCH / RISKY_LAUNCH / RUG_SETUP. Per-call ASP;
 * only meaningful for launch tokens (established tokens return NOT_A_LAUNCH).
 */

export type TrenchScan = {
  ok: boolean;
  observed_at: string;
  chain: ChainKey;
  token: string;
  verdict: "SAFE_LAUNCH" | "RISKY_LAUNCH" | "RUG_SETUP" | "NOT_A_LAUNCH" | "UNAVAILABLE";
  score: number; // 0..100 (higher = safer)
  devHoldingPct: number | null;
  bundlePct: number | null;
  sniperPct: number | null;
  devRugCount: number | null;
  reasons: string[];
  error?: string;
};

const pct = (v: any): number | null => {
  if (v == null || v === "" || v === "--") return null;
  const n = typeof v === "string" ? parseFloat(v) : Number(v);
  if (Number.isNaN(n)) return null;
  return n > 1 ? n / 100 : n;
};
const int = (v: any): number | null => {
  if (v == null || v === "") return null;
  const n = parseInt(String(v), 10);
  return Number.isNaN(n) ? null : n;
};

/** Score launch risk from the extracted metrics (pure, testable). */
export function scoreTrench(m: { devHoldingPct: number | null; bundlePct: number | null; sniperPct: number | null; devRugCount: number | null }): { verdict: TrenchScan["verdict"]; score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 100;
  if (m.devRugCount != null && m.devRugCount >= 1) { reasons.push(`Dev has ${m.devRugCount} prior rug(s) — serial operator.`); score -= 60; }
  if (m.devHoldingPct != null && m.devHoldingPct >= 0.15) { reasons.push(`Dev holds ${(m.devHoldingPct * 100).toFixed(0)}% of supply — heavy insider allocation.`); score -= 30; }
  else if (m.devHoldingPct != null && m.devHoldingPct >= 0.05) { reasons.push(`Dev holds ${(m.devHoldingPct * 100).toFixed(0)}% of supply.`); score -= 12; }
  if (m.bundlePct != null && m.bundlePct >= 0.3) { reasons.push(`${(m.bundlePct * 100).toFixed(0)}% bought in bundled launch txns — insiders front-loaded.`); score -= 30; }
  else if (m.bundlePct != null && m.bundlePct >= 0.15) { reasons.push(`${(m.bundlePct * 100).toFixed(0)}% bundled at launch.`); score -= 12; }
  if (m.sniperPct != null && m.sniperPct >= 0.2) { reasons.push(`${(m.sniperPct * 100).toFixed(0)}% held by snipers/aped wallets — dump risk.`); score -= 18; }
  score = Math.max(0, Math.round(score));
  const verdict: TrenchScan["verdict"] = score >= 70 ? "SAFE_LAUNCH" : score >= 40 ? "RISKY_LAUNCH" : "RUG_SETUP";
  if (!reasons.length) reasons.push("No major insider/bundle/sniper red flags in the launch data.");
  return { verdict, score, reasons };
}

export async function trenchScan(chain: ChainKey, token: string): Promise<TrenchScan> {
  const observed_at = new Date().toISOString();
  const base = { ok: false, observed_at, chain, token, score: 50, devHoldingPct: null, bundlePct: null, sniperPct: null, devRugCount: null, reasons: [] as string[] };
  if (!okx.isConfigured()) return { ...base, verdict: "UNAVAILABLE", error: "okx not configured", reasons: ["OKX API not configured."] };
  try {
    const [mp, adv] = await Promise.all([okx.getMemepumpToken(chain, token), okx.getAdvancedInfo(chain, token)]);
    // memepump is the launch marker: it 404s for anything that isn't a tracked recent launch.
    // Without it, advanced-info's 0-values would mislabel an established token as a "safe launch".
    if (!mp.ok) return { ...base, verdict: "NOT_A_LAUNCH", reasons: ["Not a tracked launch token (no memepump data) — use the standard token verdict instead."] };
    const d: any = mp.data ?? {};
    const a: any = adv.data ?? {};
    const devHoldingPct = pct(d.devHoldingPercent ?? a.devHoldingPercent);
    const bundlePct = pct(d.bundleRatio ?? d.bundlePercent ?? a.bundleHoldingPercent);
    const sniperPct = pct(d.sniperRatio ?? d.apedRatio ?? d.snieprRatio);
    const devRugCount = int(d.devRugCount ?? d.rugCount ?? d.creatorRugCount);
    if (devHoldingPct == null && bundlePct == null && sniperPct == null && devRugCount == null) {
      return { ...base, verdict: "NOT_A_LAUNCH", reasons: ["No launch-risk metrics available for this token (likely not a recent launch)."] };
    }
    const { verdict, score, reasons } = scoreTrench({ devHoldingPct, bundlePct, sniperPct, devRugCount });
    return { ...base, ok: true, verdict, score, devHoldingPct, bundlePct, sniperPct, devRugCount, reasons };
  } catch (e: any) {
    return { ...base, verdict: "UNAVAILABLE", error: e?.message ?? String(e), reasons: ["Could not read launch data."] };
  }
}
