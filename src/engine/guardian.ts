import { config, CHAINS, type ChainKey } from "../config.js";

/**
 * Wallet guardian — the "revoke your risky approvals" surface. Free and complete.
 *
 * Old, forgotten token approvals are one of the top ways wallets get drained: you approved a dapp once,
 * and it (or its later-compromised contract) can move your tokens forever. We pull the wallet's live
 * ERC-20 approvals from GoPlus's token-approval-security API (which reports each spender's current
 * allowance AND its risk profile in one call — no per-spender lookups, no RPC log-range limits) and
 * turn it into a prioritized revoke list: unlimited allowances and malicious/flagged spenders first.
 */

export type Approval = {
  token: string;
  tokenSymbol?: string;
  spender: string;
  spenderTag?: string; // human label for the spender (e.g. "Uniswap V3") when known
  allowance: string; // "Unlimited" or a decimal string
  unlimited: boolean;
  spenderFlags: string[]; // malicious behaviors flagged on the spender contract
  approvedAt: number | null; // unix seconds of the approval
  risk: 1 | 2 | 3 | 4 | 5;
};

export type GuardianReport = {
  ok: boolean;
  observed_at: string;
  wallet: string;
  chain: ChainKey;
  activeApprovals: number;
  unlimitedCount: number;
  maliciousSpenderCount: number;
  worstRisk: number;
  approvals: Approval[]; // sorted by risk desc — the revoke priority list
  error?: string;
};

/** Classify a single approval's risk from its allowance + spender flags (pure, unit-testable). */
export function classifyApproval(input: { unlimited: boolean; spenderFlags: string[] }): 1 | 2 | 3 | 4 | 5 {
  if (input.spenderFlags.length > 0) return 5; // malicious spender → critical regardless of amount
  if (input.unlimited) return 3; // unlimited allowance to a non-flagged spender
  return 2; // bounded allowance still worth reviewing/revoking if unused
}

/** Extract the malicious-behavior flags a GoPlus approval record carries about the spender. */
function spenderFlagsOf(addressInfo: any): string[] {
  const flags: string[] = [];
  const mb = addressInfo?.malicious_behavior;
  if (Array.isArray(mb)) flags.push(...mb.filter(Boolean));
  const doubt = addressInfo?.doubt_list;
  if (doubt === 1 || doubt === "1") flags.push("phishing_doubt");
  if (addressInfo?.is_open_source === 0 || addressInfo?.is_open_source === "0") flags.push("unverified_spender");
  return [...new Set(flags)];
}

export async function guardWallet(chain: ChainKey, wallet: string, opts: { maxPairs?: number } = {}): Promise<GuardianReport> {
  const observed_at = new Date().toISOString();
  const base: GuardianReport = { ok: false, observed_at, wallet, chain, activeApprovals: 0, unlimitedCount: 0, maliciousSpenderCount: 0, worstRisk: 0, approvals: [] };
  if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return { ...base, error: "invalid wallet address" };
  const owner = wallet.toLowerCase();
  try {
    const url = `${config.goplus.baseUrl}/api/v2/token_approval_security/${CHAINS[chain].goplusId}?addresses=${owner}`;
    const res = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(30_000) });
    const j: any = await res.json();
    if (j?.code !== 1) return { ...base, error: j?.message ?? "goplus error" };
    const result: any[] = Array.isArray(j.result) ? j.result : [];

    const approvals: Approval[] = [];
    for (const tok of result) {
      const token = String(tok.token_address || "").toLowerCase();
      for (const ap of Array.isArray(tok.approved_list) ? tok.approved_list : []) {
        const spender = String(ap.approved_contract || "").toLowerCase();
        if (!/^0x[a-fA-F0-9]{40}$/.test(spender)) continue;
        const unlimited = String(ap.approved_amount).toLowerCase() === "unlimited";
        const spenderFlags = spenderFlagsOf(ap.address_info);
        approvals.push({
          token,
          tokenSymbol: tok.token_symbol,
          spender,
          spenderTag: ap.address_info?.tag || ap.address_info?.contract_name || undefined,
          allowance: String(ap.approved_amount),
          unlimited,
          spenderFlags,
          approvedAt: ap.approved_time ? Number(ap.approved_time) : null,
          risk: classifyApproval({ unlimited, spenderFlags }),
        });
      }
    }
    approvals.sort((a, b) => b.risk - a.risk || Number(b.unlimited) - Number(a.unlimited) || (b.approvedAt ?? 0) - (a.approvedAt ?? 0));
    const capped = approvals.slice(0, opts.maxPairs ?? 100);

    return {
      ok: true, observed_at, wallet: owner, chain,
      activeApprovals: capped.length,
      unlimitedCount: capped.filter((a) => a.unlimited).length,
      maliciousSpenderCount: capped.filter((a) => a.spenderFlags.length > 0).length,
      worstRisk: capped.reduce((m, a) => Math.max(m, a.risk), 0),
      approvals: capped,
    };
  } catch (e: any) {
    return { ...base, wallet: owner, error: e?.message ?? String(e) };
  }
}
