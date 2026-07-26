import type { ChainKey } from "../config.js";
import { preTxGuardian } from "../actionguard/pretx.js";
import { chat } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";

/**
 * Transaction Deep Report — "what will this transaction actually DO to me, before I sign it?" It runs the
 * pre-tx guardian (decode intent → expected changes → counterparty/approval/token risk) and adds a plain
 * -English read plus an EIP-191 signature. A wallet UI shows raw calldata; we tell the agent the effect,
 * the risk, and sign the verdict so a caller can gate the signature on it.
 */

export type TxReport = {
  ok: boolean;
  observed_at: string;
  decision: "ALLOW" | "REVIEW" | "BLOCK";
  headline: string; // plain-English "what this does to you"
  expected_changes: string[];
  risks: { severity: number; code: string; detail: string }[];
  token_verdict: { verdict: string; score: number } | null;
  intent: unknown;
  signed: SignedReceipt | null;
  disclaimer: string;
};

export async function txReport(chain: ChainKey, tx: { to: string; from?: string; data?: string | null; value?: string | null }): Promise<TxReport> {
  const observed_at = new Date().toISOString();
  const g = await preTxGuardian(chain, tx);

  // Plain-English synthesis of the concrete effects + risks the guardian already decoded (facts only).
  let headline = g.summary || "";
  try {
    const r = await chat(
      [
        { role: "system", content: "You explain, in ONE plain sentence, what signing this transaction will do to the user and whether to be careful. Use ONLY the provided decoded effects and risks — never invent." },
        { role: "user", content: `Decision: ${g.decision}\nExpected changes: ${JSON.stringify(g.expected_changes)}\nRisks: ${JSON.stringify(g.risks)}\nToken verdict: ${JSON.stringify(g.token_verdict ?? null)}` },
      ],
      { tier: "strong", maxTokens: 160, temperature: 0.2 }
    );
    if (r.content?.trim()) headline = r.content.trim();
  } catch { /* keep guardian summary */ }

  const signed = await signReceipt({ kind: "tx_report", chain, to: tx.to, decision: g.decision, expected_changes: g.expected_changes, risks: g.risks, token_verdict: g.token_verdict ?? null, observed_at });
  return {
    ok: g.ok,
    observed_at,
    decision: g.decision,
    headline,
    expected_changes: g.expected_changes,
    risks: g.risks,
    token_verdict: g.token_verdict ?? null,
    intent: g.intent,
    signed,
    disclaimer: "Informational only. Not financial advice.",
  };
}
