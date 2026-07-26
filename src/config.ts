import "dotenv/config";

function req(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}
function opt(name: string): string | undefined {
  return process.env[name] || undefined;
}

export const config = {
  zg: {
    apiKey: req("ZG_COMPUTE_API_KEY"),
    baseUrl: "https://router-api.0g.ai/v1",
    models: {
      // model router — best-fit per task tier
      cheap: "deepseek-v4-flash", // flag tier, classification, extraction
      strong: "minimax-m3", // fusion reasoning, reports
      alt: "glm-5.2", // jury diversity
      reasoning: "deepseek-v4-pro", // hardest committee reasoning
    },
  },
  alchemyKey: req("ALCHEMY_API_KEY"),
  heliusKey: req("HELIUS_API_KEY"),
  goplus: {
    appKey: req("GOPLUS_APP_KEY"),
    appSecret: req("GOPLUS_APP_SECRET"),
    baseUrl: "https://api.gopluslabs.io",
  },
  okx: {
    accessKey: req("OKX_ONCHAINOS_ACCESS_KEY"),
    mcpUrl: opt("OKX_ONCHAINOS_MCP_URL"),
    base: "https://web3.okx.com",
    // Full OKX API creds (from developer portal) — enable the signed Market API (clusters, smart-money, PnL).
    apiKey: opt("OKX_API_KEY"),
    secretKey: opt("OKX_SECRET_KEY"),
    passphrase: opt("OKX_PASSPHRASE"),
    project: opt("OKX_PROJECT"),
  },
  wallets: {
    evmAddress: opt("EVM_WALLET_ADDRESS"),
    evmPrivateKey: opt("EVM_WALLET_PRIVATE_KEY"),
    solanaAddress: opt("SOLANA_WALLET_ADDRESS"),
  },
} as const;

/** EVM chain registry — chainId, name, and an Alchemy RPC URL. */
export const CHAINS = {
  ethereum: { id: 1, alchemy: "eth-mainnet", goplusId: "1" },
  bsc: { id: 56, alchemy: "bnb-mainnet", goplusId: "56" },
  base: { id: 8453, alchemy: "base-mainnet", goplusId: "8453" },
  arbitrum: { id: 42161, alchemy: "arb-mainnet", goplusId: "42161" },
  polygon: { id: 137, alchemy: "polygon-mainnet", goplusId: "137" },
  xlayer: { id: 196, alchemy: null, goplusId: "196", rpc: "https://rpc.xlayer.tech" },
} as const;
export type ChainKey = keyof typeof CHAINS;

/**
 * What each chain can actually support, as opposed to what it is listed under.
 *
 * X Layer has no Alchemy endpoint (`alchemy: null`), so asset-transfer history is unavailable, and
 * GoPlus's approval API rejects chain 196 outright with "Main chain does not exist!". A wallet
 * assessment there therefore has no inputs at all — which is how a signed "HEALTHY, clean footprint"
 * verdict was produced for a wallet nothing was known about. Services that need these sources check
 * this map first and say so, rather than silently treating missing data as a clean result.
 */
export const CHAIN_DATA_COVERAGE: Record<ChainKey, { approvals: boolean; transferHistory: boolean }> = {
  ethereum: { approvals: true, transferHistory: true },
  bsc: { approvals: true, transferHistory: true },
  base: { approvals: true, transferHistory: true },
  arbitrum: { approvals: true, transferHistory: true },
  polygon: { approvals: true, transferHistory: true },
  xlayer: { approvals: false, transferHistory: false },
};

/** Chains where a wallet risk assessment can actually be performed. */
export function chainsWithWalletCoverage(): ChainKey[] {
  return (Object.keys(CHAIN_DATA_COVERAGE) as ChainKey[])
    .filter((c) => CHAIN_DATA_COVERAGE[c].approvals || CHAIN_DATA_COVERAGE[c].transferHistory);
}

export function alchemyRpc(chain: ChainKey): string {
  const c = CHAINS[chain];
  if ("rpc" in c && c.rpc) return c.rpc;
  if (!c.alchemy) throw new Error(`No RPC configured for ${chain}`);
  return `https://${c.alchemy}.g.alchemy.com/v2/${config.alchemyKey}`;
}
