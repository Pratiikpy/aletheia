import type { ChainKey } from "../config.js";
import { addressSecurity } from "../adapters/deployer.js";
import { alchemyRpc } from "../config.js";
import { walletPnl } from "../engine/pnl.js";

/**
 * Counterparty check — before an agent transacts with an address/service/wallet, vet it. We flag KNOWN-bad
 * (GoPlus address-security: phishing, scam, sanctioned…), detect throwaway/fresh wallets, and read the
 * address's real on-chain footprint (nonce, trade history). Honest by design: we can prove BAD, but not
 * prove trust — a clean address is CLEAR, not "trusted". ERC-8004 agent-identity/reputation slots in later.
 */

export type CounterpartyCheck = {
  ok: boolean;
  observed_at: string;
  chain: ChainKey;
  address: string;
  verdict: "FLAGGED" | "THIN" | "CLEAR";
  malicious_flags: string[];
  tx_count: number | null;
  is_contract: boolean | null;
  realized_trades: number | null;
  reasons: string[];
  summary: string;
  error?: string;
};

async function rpc(chain: ChainKey, method: string, params: any[]): Promise<any> {
  const res = await fetch(alchemyRpc(chain), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(30_000) });
  const j: any = await res.json();
  if (j.error) throw new Error(j.error.message ?? "rpc error");
  return j.result;
}

export async function checkCounterparty(chain: ChainKey, address: string): Promise<CounterpartyCheck> {
  const observed_at = new Date().toISOString();
  const base = { ok: false, observed_at, chain, address, malicious_flags: [] as string[], tx_count: null as number | null, is_contract: null as boolean | null, realized_trades: null as number | null, reasons: [] as string[] };
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return { ...base, verdict: "THIN", summary: "Invalid address.", error: "invalid address" };
  const addr = address.toLowerCase();
  try {
    const [sec, nonceHex, code, pnl] = await Promise.all([
      addressSecurity(chain, addr).catch(() => ({ flags: [] as string[], maliciousContracts: null })),
      rpc(chain, "eth_getTransactionCount", [addr, "latest"]).catch(() => null),
      rpc(chain, "eth_getCode", [addr, "latest"]).catch(() => null),
      walletPnl(chain, addr).catch(() => null),
    ]);
    const txCount = nonceHex != null ? parseInt(nonceHex, 16) : null;
    // EIP-7702: an EOA can carry a delegation designator (0xef0100…) — it has "code" but is NOT a contract.
    const isDelegatedEoa = code != null && /^0xef0100/i.test(code);
    const isContract = code == null ? null : isDelegatedEoa ? false : code !== "0x" && code !== "0x0";
    const realizedTrades = pnl?.ok ? pnl.realizedTokens : null;
    const reasons: string[] = [];
    if (isDelegatedEoa) reasons.push("EOA with an EIP-7702 delegation set (smart-account features); not a deployed contract.");

    if (sec.flags.length > 0) reasons.push(`Flagged by address-security for: ${sec.flags.join(", ").replace(/_/g, " ")}.`);
    if (sec.maliciousContracts != null && sec.maliciousContracts > 0) reasons.push(`Has deployed ${sec.maliciousContracts} known-malicious contract(s).`);
    if (!sec.flags.length && txCount != null && txCount <= 3 && !isContract) reasons.push(`Brand-new wallet (${txCount} txns) — no history to judge.`);

    let verdict: CounterpartyCheck["verdict"];
    if (sec.flags.length > 0 || (sec.maliciousContracts ?? 0) > 0) verdict = "FLAGGED";
    else if (txCount != null && txCount <= 3 && !isContract) verdict = "THIN";
    else verdict = "CLEAR";
    if (verdict === "CLEAR") reasons.push(`Established on-chain footprint (${txCount ?? "?"} txns${realizedTrades ? `, ${realizedTrades} traded tokens` : ""}); no known-malicious flags. (Absence of flags is not proof of trust.)`);

    return {
      ...base, ok: true, verdict,
      malicious_flags: sec.flags, tx_count: txCount, is_contract: isContract, realized_trades: realizedTrades, reasons,
      summary:
        verdict === "FLAGGED" ? `BLOCK — counterparty is flagged malicious: ${sec.flags.join(", ").replace(/_/g, " ") || "serial malicious deployer"}.` :
        verdict === "THIN" ? "REVIEW — brand-new address with no track record; treat as unverified." :
        "CLEAR — no known-malicious flags and an established footprint (not a guarantee of trustworthiness).",
    };
  } catch (e: any) {
    return { ...base, verdict: "THIN", summary: "Counterparty check failed.", error: e?.message ?? String(e) };
  }
}
