import { alchemyRpc, type ChainKey } from "../config.js";

/**
 * Insider-cluster / sybil detection — Aletheia's self-computed answer to Bubblemaps "Magic Nodes".
 *
 * The signal every trader wants pre-buy: "is the float actually held by one entity wearing many hats?"
 * We reconstruct it from free Alchemy asset-transfer history using two independent linkage proofs:
 *   1. COMMON FUNDER  — N top holders were first funded by the same non-exchange EOA (or by the deployer).
 *   2. SAME-BLOCK BUY — N top holders first received the token in the exact same block (coordinated seed).
 * A group linked by either proof is a cluster; its members' balances are summed into one effective holder.
 * Deployer-funded clusters and high combined-supply clusters are the dangerous ones (stealth insider float).
 *
 * Everything here is keyless and reproducible: the same holder set + chain history yields the same clusters.
 */

/** Addresses that fund thousands of unrelated wallets — shared funding through them is NOT a cluster link. */
const NEUTRAL_FUNDERS = new Set(
  [
    // CEX hot wallets (ETH/EVM)
    "0x28c6c06298d514db089934071355e5743bf21d60", // Binance 14
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549", // Binance 15
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d", // Binance 16
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f", // Binance 17
    "0x9696f59e4d72e237be84ffd425dcad154bf96976", // Binance 18
    "0x4976a4a02f38326660d17bf34b431dc6e2eb2327", // Binance 20
    "0xf977814e90da44bfa03b6295a0616a897441acec", // Binance 8 (cold)
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3", // Coinbase 1
    "0x503828976d22510aad0201ac7ec88293211d23da", // Coinbase 2
    "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740", // Coinbase 3
    "0x3cd751e6b0078be393132286c442345e5dc49699", // Coinbase 4
    "0xa910f92acdaf488fa6ef02174fb86208 ad7722ba".replace(/\s/g, ""),
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b", // OKX
    "0x236f9f97e0e62388479bf9e5ba4889e46b0273c3", // OKX 2
    "0x98ec059dc3adfbdd63429454aeb0c990fba4a128", // OKX 3
    "0x2faf487a4414fe77e2327f0bf4ae2a264a776ad2", // FTX (historical)
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe", // Gate.io
    "0x1c4b70a3968436b9a0a9cf5205c787eb81bb558c", // Gate.io 2
    // Common routers / null
    "0x0000000000000000000000000000000000000000",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
    "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 Router
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", // Uniswap Universal Router
    "0x10ed43c718714eb63d5aa57b78b54704e256024e", // Pancake Router
  ].map((a) => a.toLowerCase())
);

export type ClusterMember = {
  address: string;
  percent: number; // share of supply (0..1)
  funder: string | null;
  acquiredBlock: number | null;
};

export type Cluster = {
  id: string; // deterministic label (funder or block anchor)
  linkage: "common_funder" | "same_block_buy";
  anchor: string; // the shared funder address, or the shared block number
  members: string[]; // holder addresses
  combinedPercent: number; // summed share of supply (0..1)
  funderIsDeployer: boolean; // the shared funder is the token's deployer → seeded insider float
};

export type ClusterAnalysis = {
  ok: boolean;
  observed_at: string;
  analyzedHolders: number; // how many top holders we resolved history for
  clusters: Cluster[]; // sorted by combinedPercent desc
  largestClusterPercent: number; // 0..1 — headline number
  deployerSeededPercent: number; // 0..1 supply in clusters the deployer funded
  error?: string;
};

async function rpc(chain: ChainKey, method: string, params: any[]): Promise<any> {
  const res = await fetch(alchemyRpc(chain), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  const j: any = await res.json();
  if (j.error) throw new Error(j.error.message ?? "rpc error");
  return j.result;
}

/** First inbound native/erc20 transfer to `addr` → who seeded this wallet, and when. */
async function firstFunding(chain: ChainKey, addr: string): Promise<{ funder: string | null }> {
  const r = await rpc(chain, "alchemy_getAssetTransfers", [
    { toAddress: addr, category: ["external", "erc20"], order: "asc", maxCount: "0x1", withMetadata: true },
  ]).catch(() => null);
  const first = r?.transfers?.[0];
  return { funder: first?.from ? String(first.from).toLowerCase() : null };
}

/** First time `addr` received THIS token → the block it entered the position (coordination anchor). */
async function firstTokenReceipt(chain: ChainKey, token: string, addr: string): Promise<{ block: number | null }> {
  const r = await rpc(chain, "alchemy_getAssetTransfers", [
    { toAddress: addr, contractAddresses: [token], category: ["erc20"], order: "asc", maxCount: "0x1", withMetadata: true },
  ]).catch(() => null);
  const first = r?.transfers?.[0];
  const block = first?.blockNum ? parseInt(first.blockNum, 16) : null;
  return { block: Number.isNaN(block as any) ? null : block };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]!);
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Analyze the top holders of `token` for insider/sybil clusters.
 * `holders`: from GoPlus (address + percent). `creator`: deployer address (to flag seeded float).
 * Only EOAs are analyzed — LP pools, locked, and contract holders are excluded upstream by the caller.
 */
export async function analyzeClusters(
  chain: ChainKey,
  token: string,
  holders: { address: string; percent: number }[],
  creator: string | null | undefined,
  opts: { topN?: number } = {}
): Promise<ClusterAnalysis> {
  const observed_at = new Date().toISOString();
  // xlayer uses a public RPC without alchemy_getAssetTransfers — skip gracefully.
  if (!CHAINS_WITH_TRANSFERS.has(chain)) {
    return { ok: false, observed_at, analyzedHolders: 0, clusters: [], largestClusterPercent: 0, deployerSeededPercent: 0, error: "asset-transfer history unavailable on this chain" };
  }
  const topN = opts.topN ?? 20;
  const targets = holders
    .filter((h) => /^0x[a-fA-F0-9]{40}$/.test(h.address || ""))
    .slice(0, topN);
  if (targets.length < 2) {
    return { ok: true, observed_at, analyzedHolders: targets.length, clusters: [], largestClusterPercent: 0, deployerSeededPercent: 0 };
  }

  try {
    const members: ClusterMember[] = await mapLimit(targets, 6, async (h) => {
      const addr = h.address.toLowerCase();
      const [{ funder }, { block }] = await Promise.all([firstFunding(chain, addr), firstTokenReceipt(chain, token, addr)]);
      return { address: addr, percent: h.percent, funder, acquiredBlock: block };
    });

    const { clusters, largestClusterPercent, deployerSeededPercent } = clusterMembers(members, creator);
    return { ok: true, observed_at, analyzedHolders: members.length, clusters, largestClusterPercent, deployerSeededPercent };
  } catch (e: any) {
    return { ok: false, observed_at, analyzedHolders: 0, clusters: [], largestClusterPercent: 0, deployerSeededPercent: 0, error: e?.message ?? String(e) };
  }
}

const CHAINS_WITH_TRANSFERS = new Set<ChainKey>(["ethereum", "bsc", "base", "arbitrum", "polygon"]);

/**
 * Pure grouping step (no I/O) — deterministic and unit-testable.
 * Given holders with their resolved funder + first-token-receipt block, group them into clusters by
 * shared non-neutral funder or shared receipt block, and roll up combined supply share.
 */
export function clusterMembers(
  members: ClusterMember[],
  creator: string | null | undefined
): { clusters: Cluster[]; largestClusterPercent: number; deployerSeededPercent: number } {
  const creatorLc = creator?.toLowerCase() ?? null;

  const byFunder = new Map<string, ClusterMember[]>();
  for (const m of members) {
    const f = m.funder?.toLowerCase();
    if (!f || NEUTRAL_FUNDERS.has(f)) continue;
    if (!byFunder.has(f)) byFunder.set(f, []);
    byFunder.get(f)!.push(m);
  }
  const byBlock = new Map<number, ClusterMember[]>();
  for (const m of members) {
    if (m.acquiredBlock == null) continue;
    if (!byBlock.has(m.acquiredBlock)) byBlock.set(m.acquiredBlock, []);
    byBlock.get(m.acquiredBlock)!.push(m);
  }

  const clusters: Cluster[] = [];
  for (const [funder, ms] of byFunder) {
    if (ms.length < 2) continue;
    clusters.push({
      id: `funder:${funder.slice(0, 10)}`,
      linkage: "common_funder",
      anchor: funder,
      members: ms.map((m) => m.address),
      combinedPercent: ms.reduce((s, m) => s + (m.percent || 0), 0),
      funderIsDeployer: !!creatorLc && funder === creatorLc,
    });
  }
  for (const [block, ms] of byBlock) {
    if (ms.length < 2) continue;
    const key = ms.map((m) => m.address).slice().sort().join(",");
    if (clusters.some((c) => c.members.slice().sort().join(",") === key)) continue; // already a funder cluster
    clusters.push({
      id: `block:${block}`,
      linkage: "same_block_buy",
      anchor: String(block),
      members: ms.map((m) => m.address),
      combinedPercent: ms.reduce((s, m) => s + (m.percent || 0), 0),
      funderIsDeployer: false,
    });
  }

  clusters.sort((a, b) => b.combinedPercent - a.combinedPercent);
  return {
    clusters,
    largestClusterPercent: clusters[0]?.combinedPercent ?? 0,
    deployerSeededPercent: clusters.filter((c) => c.funderIsDeployer).reduce((s, c) => s + c.combinedPercent, 0),
  };
}
