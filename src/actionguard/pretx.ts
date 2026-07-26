import type { ChainKey } from "../config.js";
import { decodeTxIntent, evaluateTx, type TxIntent } from "../engine/firewall.js";

/**
 * Pre-Transaction Guardian (Hypernative-style) — before an agent signs, decode the transaction, run the
 * firewall checks (malicious counterparty, unlimited approval, AVOID token), AND state the expected
 * effect in plain language (token/permission changes) so the caller sees exactly what it authorizes.
 * Returns ALLOW / REVIEW / BLOCK. Reuses Aletheia's firewall + token engine. Per-call ASP.
 */

export type PreTxResult = {
  ok: boolean;
  observed_at: string;
  decision: "ALLOW" | "REVIEW" | "BLOCK";
  intent: TxIntent;
  expected_changes: string[]; // plain-language effect of the tx
  risks: { severity: number; code: string; detail: string }[];
  summary: string;
  token_verdict?: { verdict: string; score: number } | null;
  error?: string;
};

const short = (a: string) => (a && a.length > 12 ? a.slice(0, 6) + "…" + a.slice(-4) : a);

/** Derive the expected on-chain effect from a decoded intent (pure, testable). */
export function expectedChanges(intent: TxIntent): string[] {
  switch (intent.kind) {
    case "approve":
      return [`Grants ${short(intent.spender)} an allowance of ${intent.unlimited ? "UNLIMITED" : intent.amount.toString()} on token ${short(intent.token)} — the spender can move that amount of your tokens at any time.`];
    case "approve_all":
      return [`Grants ${short(intent.operator)} control over ALL your NFTs in collection ${short(intent.token)}.`];
    case "erc20_transfer":
      return [`Sends ${intent.amount.toString()} token units of ${short(intent.token)} to ${short(intent.recipient)}.`];
    case "native_transfer":
      return [`Sends ${(Number(intent.valueWei) / 1e18).toFixed(6)} native to ${short(intent.to)}.`];
    case "contract_call":
      return [`Calls function ${intent.selector} on contract ${short(intent.to)} — effects depend on the contract; review the target's verdict below.`];
    default:
      return ["Unrecognized transaction shape."];
  }
}

export async function preTxGuardian(chain: ChainKey, tx: { to: string; from?: string; data?: string | null; value?: string | null }): Promise<PreTxResult> {
  const observed_at = new Date().toISOString();
  try {
    const fw = await evaluateTx(chain, tx);
    const decision = fw.decision === "WARN" ? "REVIEW" : fw.decision; // Guardian vocabulary
    const intent = decodeTxIntent(tx);
    return {
      ok: fw.ok, observed_at, decision,
      intent: fw.intent,
      expected_changes: expectedChanges(intent),
      risks: fw.risks.map((r) => ({ severity: r.severity, code: r.code, detail: r.detail })),
      summary: fw.summary,
      token_verdict: fw.tokenVerdict ?? null,
      error: fw.error,
    };
  } catch (e: any) {
    return { ok: false, observed_at, decision: "REVIEW", intent: { kind: "contract_call", to: tx.to, selector: "0x" } as any, expected_changes: [], risks: [], summary: "Guardian check failed — do not assume safe.", error: e?.message ?? String(e) };
  }
}
