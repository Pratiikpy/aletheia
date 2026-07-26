import type { ChainKey } from "../config.js";
import { guardWallet } from "./guardian.js";
import { airdropSybilCheck } from "./airdrop.js";
import { walletPnl } from "./pnl.js";
import { gradeTrader } from "./copytrade.js";
import { chatJson } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";

/**
 * Wallet Deep Report — one signed answer to "who is this wallet?" It fuses four engines we already own —
 * live approvals (revoke risk), airdrop/sybil footprint, fee-adjusted PnL, and a copyworthiness grade —
 * into a structured fact-set + an AI classification + what-to-do, then signs it. A data-explorer dumps a
 * wallet's transactions; a scanner scores its approvals. We answer the actual question and prove it.
 */

export type WalletFacts = {
  wallet: string;
  chain: string;
  approvals: { active: number; unlimited: number; malicious_spenders: number; worst_risk: number; revoke_recommended: number } | null;
  sybil: { label: string; score: number | null; reasons: string[] } | null;
  trading: { native_symbol: string; trades: number; realized_native: number; net_native: number; win_rate: number | null; tokens_traded: number } | null;
  trader_grade: { label: string; score: number } | null;
};

export type WalletReport = {
  ok: boolean;
  observed_at: string;
  wallet: string;
  chain: string;
  classification: "SMART_MONEY" | "NORMAL_USER" | "AIRDROP_FARMER" | "RISKY" | "MIXED" | "UNKNOWN";
  // INSUFFICIENT_DATA is a real verdict, not a placeholder: on a chain where the approvals API and
  // transfer history are both unavailable there is nothing to base a risk call on, and reporting
  // "HEALTHY" there is worse than reporting nothing.
  risk: "HEALTHY" | "CAUTION" | "AT_RISK" | "INSUFFICIENT_DATA";
  headline: string;
  what_to_do: string;
  facts: WalletFacts;
  /** Which underlying checks actually returned data. The verdict rests only on these. */
  checks_run: { approvals: boolean; sybil: boolean; trading: boolean };
  checks_unavailable: string[];
  signed: SignedReceipt | null;
  disclaimer: string;
};

export async function walletReport(chain: ChainKey, wallet: string): Promise<WalletReport> {
  const observed_at = new Date().toISOString();
  const [aRes, sRes, pRes] = await Promise.allSettled([
    guardWallet(chain, wallet),
    airdropSybilCheck(chain, wallet),
    walletPnl(chain, wallet),
  ]);
  const g: any = aRes.status === "fulfilled" ? aRes.value : null;
  const s: any = sRes.status === "fulfilled" ? sRes.value : null;
  const p: any = pRes.status === "fulfilled" ? pRes.value : null;
  const grade = p ? gradeTrader({ netNative: p.netNative, winRate: p.winRate, realizedTokens: p.realizedTokens, tradeCount: p.tradeCount }) : null;

  const facts: WalletFacts = {
    wallet,
    chain,
    approvals: g ? { active: g.activeApprovals, unlimited: g.unlimitedCount, malicious_spenders: g.maliciousSpenderCount, worst_risk: g.worstRisk, revoke_recommended: (g.maliciousSpenderCount ?? 0) + (g.unlimitedCount ?? 0) } : null,
    sybil: s ? { label: s.label, score: s.sybilScore ?? s.score ?? null, reasons: Array.isArray(s.reasons) ? s.reasons : [] } : null,
    trading: p ? { native_symbol: p.nativeSymbol, trades: p.tradeCount, realized_native: p.realizedNative, net_native: p.netNative, win_rate: p.winRate, tokens_traded: p.realizedTokens } : null,
    trader_grade: grade ? { label: grade.label, score: grade.score } : null,
  };

  // Deterministic risk + classification first — always correct even if the AI layer fails.
  const sybilFlag = s?.label === "LIKELY_SYBIL";
  // Every condition below reads a field off a result, so a data source that failed leaves them all
  // `undefined` and every condition false — yielding "HEALTHY" from no data at all. On a chain where
  // the approvals API and transfer history are both unavailable that is a signed all-clear backed by
  // nothing. Only a check that actually ran can support a conclusion about the wallet.
  const ran = (r: any) => !!r && (r as any).ok !== false && !(r as any).error;
  const checksRun = { approvals: ran(g), sybil: ran(s), trading: ran(p) };
  const risk: WalletReport["risk"] =
    (checksRun.approvals && ((g?.maliciousSpenderCount ?? 0) > 0 || (g?.worstRisk ?? 0) >= 3))
      || (checksRun.sybil && sybilFlag) ? "AT_RISK" :
    checksRun.approvals && (g?.unlimitedCount ?? 0) > 0 ? "CAUTION" :
    !checksRun.approvals && !checksRun.sybil ? "INSUFFICIENT_DATA" : "HEALTHY";
  let classification: WalletReport["classification"] =
    grade?.label === "SMART_MONEY" ? "SMART_MONEY" :
    sybilFlag ? "AIRDROP_FARMER" :
    (g?.maliciousSpenderCount ?? 0) > 0 ? "RISKY" :
    p ? "NORMAL_USER" : "UNKNOWN";

  // AI synthesizer: sharpen the classification + a plain-English what-to-do, grounded ONLY in the facts.
  let headline = "";
  let what_to_do = "";
  try {
    const res = await chatJson<{ classification: string; headline: string; what_to_do: string }>(
      [
        { role: "system", content: "You classify an on-chain wallet from FACTS ONLY (never invent). Return JSON {classification: one of SMART_MONEY|NORMAL_USER|AIRDROP_FARMER|RISKY|MIXED, headline: one plain sentence on who this wallet is, what_to_do: one plain sentence of advice for someone dealing with / considering copying it}." },
        { role: "user", content: JSON.stringify(facts) },
      ],
      { tier: "strong", maxTokens: 300, temperature: 0.2 }
    );
    const c = String(res.data?.classification ?? "").toUpperCase();
    if (["SMART_MONEY", "NORMAL_USER", "AIRDROP_FARMER", "RISKY", "MIXED"].includes(c)) classification = c as WalletReport["classification"];
    headline = res.data?.headline ?? "";
    what_to_do = res.data?.what_to_do ?? "";
  } catch { /* fall back to deterministic below */ }

  const checks_unavailable = Object.entries(checksRun).filter(([, ok]) => !ok).map(([k]) => k);

  // When nothing could be checked, the headline must say so instead of describing a wallet we have no
  // information about — and it must override whatever the AI layer wrote, since the model was handed
  // all-null facts and will still produce a confident-sounding sentence from them.
  if (risk === "INSUFFICIENT_DATA") {
    headline = `Cannot assess this wallet on ${chain}: ${checks_unavailable.join(", ")} unavailable.`;
    what_to_do = "Treat as unverified — this is not an all-clear. Re-check on a chain where approval "
      + "and transfer history are available before relying on it.";
  } else if (!headline) {
    headline =
      classification === "SMART_MONEY" ? `Proven profitable trader (grade ${grade?.score ?? "?"}/100, net ${facts.trading?.net_native ?? "?"} ${facts.trading?.native_symbol ?? ""}).` :
      classification === "AIRDROP_FARMER" ? "Airdrop-farming footprint — hub-funded with thin, templated activity." :
      classification === "RISKY" ? "Wallet has risky/malicious approvals or associations." :
      classification === "NORMAL_USER" ? "Ordinary wallet — no smart-money track record and no major red flags." :
      "Not enough on-chain history to classify.";
  }
  if (!what_to_do) what_to_do =
    risk === "AT_RISK" ? "Do not trust or copy blindly; revoke risky approvals and treat counterparty as unverified." :
    classification === "SMART_MONEY" ? "Track record is real, but size copies to its liquidity and re-check each specific trade." :
    checks_unavailable.length ? `No urgent action from the checks that ran, but ${checks_unavailable.join(", ")} could not be checked — verify the specific interaction before proceeding.` :
    "No urgent action; verify the specific interaction before proceeding.";

  const signed = await signReceipt({ kind: "wallet_report", chain, wallet, classification, risk, checks_run: checksRun, facts, observed_at });
  return { ok: true, observed_at, wallet, chain, classification, risk, headline, what_to_do, facts,
           checks_run: checksRun, checks_unavailable, signed,
           disclaimer: "Informational only. Not financial advice." };
}
