import type { ChainKey } from "../config.js";
import { walletPnl, type WalletPnl } from "./pnl.js";

/**
 * Copy-intelligence — "is this wallet worth copying, and what is it in right now?".
 *
 * Built entirely on Aletheia's own fee-adjusted PnL engine (no paid smart-money API). We grade a wallet's
 * track record into a copyworthiness label + score, gate it on a minimum realized sample so a lucky
 * two-trade wallet can't look like alpha, and surface its current open positions (tokens it still holds).
 * The grading is pure and unit-tested; the data comes from the reconstructed on-chain trade ledger.
 */

export type TraderLabel = "SMART_MONEY" | "DECENT" | "UNPROVEN" | "UNDERWATER";

export type TraderGrade = {
  label: TraderLabel;
  score: number; // 0..100 copyworthiness
  confidence: number; // 0..1 — driven by realized sample size
  reasons: string[];
};

/** Grade a wallet's copyworthiness from its realized-PnL stats (pure, unit-testable). */
export function gradeTrader(p: Pick<WalletPnl, "netNative" | "winRate" | "realizedTokens" | "tradeCount">): TraderGrade {
  const { netNative, winRate, realizedTokens, tradeCount } = p;
  const reasons: string[] = [];
  const wr = winRate ?? 0;
  // confidence grows with realized sample; below 3 closed positions we can't judge skill from luck
  const confidence = Math.max(0.15, Math.min(1, realizedTokens / 12));

  // score: win-rate (up to 55) + profitability sign/scale (up to 45)
  let score = wr * 55;
  if (netNative > 0) score += Math.min(45, 20 + Math.log10(1 + netNative) * 12);
  else if (netNative < 0) score += Math.max(0, 12 + netNative); // small penalty floor
  score = Math.max(0, Math.min(100, Math.round(score)));

  reasons.push(`win-rate ${(wr * 100).toFixed(0)}% over ${realizedTokens} closed position(s)`);
  reasons.push(`net ${netNative >= 0 ? "+" : ""}${netNative.toFixed(3)} (fee-adjusted) across ${tradeCount} trades`);

  let label: TraderLabel;
  if (realizedTokens < 3) { label = "UNPROVEN"; reasons.push("too few closed trades to judge — treat as unproven"); }
  else if (netNative <= 0) { label = "UNDERWATER"; reasons.push("net-negative realized PnL — not currently profitable"); }
  else if (wr >= 0.5 && realizedTokens >= 5) { label = "SMART_MONEY"; reasons.push("profitable with a strong win-rate over a real sample"); }
  else { label = "DECENT"; reasons.push("net-positive but not a standout track record"); }

  return { label, score, confidence, reasons };
}

export type OpenPosition = { token: string; remaining: number; buys: number; realizedNative: number };

export type CopyIntel = {
  ok: boolean;
  observed_at: string;
  wallet: string;
  chain: ChainKey;
  grade: TraderGrade;
  pnl: WalletPnl;
  openPositions: OpenPosition[]; // tokens the wallet still holds — what to potentially copy into
  error?: string;
};

export async function copyIntel(chain: ChainKey, wallet: string): Promise<CopyIntel> {
  const observed_at = new Date().toISOString();
  const pnl = await walletPnl(chain, wallet);
  if (!pnl.ok) {
    return { ok: false, observed_at, wallet: pnl.wallet, chain, grade: gradeTrader(pnl), pnl, openPositions: [], error: pnl.error };
  }
  const openPositions: OpenPosition[] = pnl.perToken
    .filter((t) => t.remaining > 1e-9 && t.buys > 0)
    .slice(0, 15)
    .map((t) => ({ token: t.token, remaining: t.remaining, buys: t.buys, realizedNative: t.realizedNative }));
  return { ok: true, observed_at, wallet: pnl.wallet, chain, grade: gradeTrader(pnl), pnl, openPositions };
}
