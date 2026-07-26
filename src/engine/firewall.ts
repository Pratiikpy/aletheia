import { toFunctionSelector } from "viem";
import type { ChainKey } from "../config.js";
import { addressSecurity } from "../adapters/deployer.js";
import { erc20Meta } from "../adapters/rpc.js";
import { tokenVerdict } from "./verdict.js";

/**
 * Agent-transaction firewall — a pre-signing gate for autonomous agents (and wallets).
 *
 * Before an agent signs, it asks Aletheia: "should I execute THIS transaction?". We decode the intent from
 * the calldata and run the matching engine checks, then return ALLOW / WARN / BLOCK with reasons:
 *   - buying/interacting with a token  → full token verdict (AVOID ⇒ BLOCK).
 *   - approve(spender, amount)         → is the spender malicious? is it an unlimited allowance? is the
 *                                        token itself a rug? (malicious spender or AVOID token ⇒ BLOCK).
 *   - sending value / ERC-20 transfer  → is the recipient a known phishing/scam/sanctioned address?
 *   - call into an unverified contract → WARN.
 *
 * The decode step is pure and unit-tested; the checks reuse the same evidence-linked engine as verdicts.
 */

const SEL = {
  approve: toFunctionSelector("approve(address,uint256)"),
  transfer: toFunctionSelector("transfer(address,uint256)"),
  transferFrom: toFunctionSelector("transferFrom(address,address,uint256)"),
  setApprovalForAll: toFunctionSelector("setApprovalForAll(address,bool)"),
};
const MAX_UINT = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

export type TxIntent =
  | { kind: "native_transfer"; to: string; valueWei: bigint }
  | { kind: "approve"; token: string; spender: string; amount: bigint; unlimited: boolean }
  | { kind: "approve_all"; token: string; operator: string }
  | { kind: "erc20_transfer"; token: string; recipient: string; amount: bigint }
  | { kind: "contract_call"; to: string; selector: string };

/** Decode a proposed tx into a high-level intent (pure, unit-testable). */
export function decodeTxIntent(tx: { to: string; data?: string | null; value?: string | null }): TxIntent {
  const to = (tx.to || "").toLowerCase();
  const data = (tx.data || "0x").toLowerCase();
  const valueWei = tx.value ? BigInt(tx.value) : 0n;
  const arg = (i: number) => data.slice(10 + i * 64, 10 + (i + 1) * 64); // 32-byte word i (hex, no 0x)
  const addrFromWord = (w: string) => "0x" + w.slice(24); // last 20 bytes

  if (!data || data === "0x" || data.length < 10) {
    return { kind: "native_transfer", to, valueWei };
  }
  const selector = data.slice(0, 10);
  if (selector === SEL.approve) {
    const spender = addrFromWord(arg(0));
    const amtHex = arg(1);
    const amount = amtHex ? BigInt("0x" + amtHex) : 0n;
    return { kind: "approve", token: to, spender, amount, unlimited: amtHex === MAX_UINT };
  }
  if (selector === SEL.setApprovalForAll) {
    return { kind: "approve_all", token: to, operator: addrFromWord(arg(0)) };
  }
  if (selector === SEL.transfer) {
    return { kind: "erc20_transfer", token: to, recipient: addrFromWord(arg(0)), amount: arg(1) ? BigInt("0x" + arg(1)) : 0n };
  }
  return { kind: "contract_call", to, selector };
}

export type FirewallRisk = { severity: 1 | 2 | 3 | 4 | 5; code: string; detail: string };
export type FirewallResult = {
  ok: boolean;
  observed_at: string;
  decision: "ALLOW" | "WARN" | "BLOCK";
  intent: TxIntent;
  risks: FirewallRisk[];
  summary: string;
  tokenVerdict?: { verdict: string; score: number } | null;
  error?: string;
};

/** Map the worst risk severity to a decision (pure). */
export function decideFromRisks(risks: FirewallRisk[]): "ALLOW" | "WARN" | "BLOCK" {
  const max = risks.reduce((m, r) => Math.max(m, r.severity), 0);
  if (max >= 4) return "BLOCK";
  if (max >= 2) return "WARN";
  return "ALLOW";
}

const bigintToJson = (i: TxIntent): any => JSON.parse(JSON.stringify(i, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

/** Evaluate a proposed transaction and return ALLOW / WARN / BLOCK with evidence-linked reasons. */
export async function evaluateTx(chain: ChainKey, tx: { to: string; from?: string; data?: string | null; value?: string | null }): Promise<FirewallResult> {
  const observed_at = new Date().toISOString();
  const intent = decodeTxIntent(tx);
  const risks: FirewallRisk[] = [];
  let tokenV: { verdict: string; score: number } | null = null;

  const checkAddress = async (addr: string, label: string) => {
    if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) return;
    const sec = await addressSecurity(chain, addr).catch(() => ({ flags: [] as string[], maliciousContracts: null }));
    if (sec.flags.length > 0) risks.push({ severity: 5, code: `malicious_${label}`, detail: `${label} ${addr} is flagged: ${sec.flags.join(", ").replace(/_/g, " ")}` });
  };
  const checkTokenSafety = async (token: string) => {
    if (!/^0x[a-fA-F0-9]{40}$/.test(token)) return;
    const v = await tokenVerdict(chain, token, "full").catch(() => null);
    if (v) {
      tokenV = { verdict: v.verdict, score: v.score };
      if (v.verdict === "AVOID") risks.push({ severity: 5, code: "token_avoid", detail: `Target token is AVOID (score ${v.score}): ${v.summary.slice(0, 120)}` });
      else if (v.verdict === "CAUTION") risks.push({ severity: 3, code: "token_caution", detail: `Target token is CAUTION (score ${v.score}).` });
    }
  };

  try {
    if (intent.kind === "native_transfer") {
      await checkAddress(intent.to, "recipient");
      // sending to a contract with no calldata is unusual; sending to EOA is normal
    } else if (intent.kind === "erc20_transfer") {
      await checkAddress(intent.recipient, "recipient");
    } else if (intent.kind === "approve" || intent.kind === "approve_all") {
      const spender = intent.kind === "approve" ? intent.spender : intent.operator;
      await Promise.all([checkAddress(spender, "spender"), checkTokenSafety(intent.token)]);
      if (intent.kind === "approve" && intent.unlimited) {
        risks.push({ severity: 2, code: "unlimited_approval", detail: `Unlimited allowance to ${spender} — the spender can move your entire balance of this token at any time.` });
      }
      if (intent.kind === "approve_all") {
        risks.push({ severity: 3, code: "approval_for_all", detail: `setApprovalForAll grants ${intent.operator} control over ALL your NFTs in this collection.` });
      }
    } else if (intent.kind === "contract_call") {
      // a call into a token/contract — run the token verdict + check verification
      await checkTokenSafety(intent.to);
      const meta = await erc20Meta(chain, intent.to as `0x${string}`).catch(() => null);
      if (meta && !meta.isContract) risks.push({ severity: 2, code: "not_a_contract", detail: `Target ${intent.to} has no code — a call here will silently do nothing or is misdirected.` });
    }

    const decision = decideFromRisks(risks);
    const summary =
      decision === "BLOCK" ? `BLOCK — ${risks.find((r) => r.severity >= 4)?.detail ?? "high-risk transaction"}` :
      decision === "WARN" ? `WARN — ${risks.map((r) => r.code).join(", ")}. Review before signing.` :
      "ALLOW — no material risk detected in this transaction.";

    return { ok: true, observed_at, decision, intent: bigintToJson(intent), risks, summary, tokenVerdict: tokenV };
  } catch (e: any) {
    return { ok: false, observed_at, decision: "WARN", intent: bigintToJson(intent), risks, summary: "Firewall check failed — do not assume safe.", tokenVerdict: tokenV, error: e?.message ?? String(e) };
  }
}
