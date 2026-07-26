import { alchemyRpc, config, CHAINS, type ChainKey } from "../config.js";

/**
 * Deployer / creator forensics — the #1 most-requested pre-trade signal.
 * Traces the deployer wallet: activity level, funding source, and whether it was funded by a mixer or
 * spun up fresh right before launch (throwaway rug pattern). Serial-rugger history comes from OKX (creds).
 */

// Known mixer / Tornado Cash addresses (ETH) — funding from these is a strong rug/scam signal.
const MIXERS = new Set(
  [
    "0x8589427373d6d84e98730d7795d8f6f8731fda16",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967",
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291",
    "0xd90e2f925da726b50c4 ed8d0fb90ad053324f31b".replace(/\s/g, ""),
  ].map((a) => a.toLowerCase())
);

export type DeployerInfo = {
  ok: boolean;
  observed_at: string;
  creator: string | null;
  txCount: number | null; // deployer wallet nonce — activity level
  funder: string | null; // who first funded the deployer
  funderIsMixer: boolean;
  firstFundedAt: string | null;
  maliciousFlags: string[]; // GoPlus address-security flags on the deployer (phishing, scam, sanctioned…)
  maliciousContractsCreated: number | null; // # of prior malicious contracts by this deployer (free serial-rugger signal)
  error?: string;
};

const MALICIOUS_FIELDS = [
  "cybercrime", "money_laundering", "financial_crime", "darkweb_transactions", "phishing_activities",
  "blacklist_doubt", "stealing_attack", "fake_kyc", "malicious_mining_activities", "sanctioned",
  "honeypot_related_address", "mixer",
] as const;

export async function addressSecurity(chain: ChainKey, addr: string): Promise<{ flags: string[]; maliciousContracts: number | null }> {
  try {
    const res = await fetch(`${config.goplus.baseUrl}/api/v1/address_security/${addr}?chain_id=${CHAINS[chain].goplusId}`, { signal: AbortSignal.timeout(30_000) });
    const j: any = await res.json();
    const r = j?.result ?? {};
    const flags = MALICIOUS_FIELDS.filter((f) => r[f] === "1");
    const mc = r.number_of_malicious_contracts_created != null ? parseInt(r.number_of_malicious_contracts_created, 10) : null;
    return { flags, maliciousContracts: Number.isNaN(mc as any) ? null : mc };
  } catch {
    return { flags: [], maliciousContracts: null };
  }
}

async function rpc(chain: ChainKey, method: string, params: any[]): Promise<any> {
  const res = await fetch(alchemyRpc(chain), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  const j: any = await res.json();
  return j.result;
}

export async function getDeployerInfo(chain: ChainKey, creator: string | null | undefined): Promise<DeployerInfo> {
  const observed_at = new Date().toISOString();
  if (!creator || !/^0x[a-fA-F0-9]{40}$/.test(creator) || creator === "0x0000000000000000000000000000000000000000") {
    return { ok: false, observed_at, creator: creator ?? null, txCount: null, funder: null, funderIsMixer: false, firstFundedAt: null, maliciousFlags: [], maliciousContractsCreated: null, error: "no creator" };
  }
  try {
    const [nonceHex, transfers, sec] = await Promise.all([
      rpc(chain, "eth_getTransactionCount", [creator, "latest"]).catch(() => null),
      rpc(chain, "alchemy_getAssetTransfers", [
        { toAddress: creator, category: ["external", "erc20"], order: "asc", maxCount: "0x5", withMetadata: true },
      ]).catch(() => null),
      addressSecurity(chain, creator),
    ]);
    const txCount = nonceHex != null ? parseInt(nonceHex, 16) : null;
    const first = transfers?.transfers?.[0];
    const funder = first?.from?.toLowerCase() ?? null;
    return {
      ok: true, observed_at, creator,
      txCount,
      funder,
      funderIsMixer: !!funder && MIXERS.has(funder),
      firstFundedAt: first?.metadata?.blockTimestamp ?? null,
      maliciousFlags: sec.flags,
      maliciousContractsCreated: sec.maliciousContracts,
    };
  } catch (e: any) {
    return { ok: false, observed_at, creator, txCount: null, funder: null, funderIsMixer: false, firstFundedAt: null, maliciousFlags: [], maliciousContractsCreated: null, error: e?.message ?? String(e) };
  }
}
