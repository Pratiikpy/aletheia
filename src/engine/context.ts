import type { ChainKey } from "../config.js";
import { getTokenSecurity, type GoPlusTokenSecurity } from "../adapters/goplus.js";
import { getMarket, type MarketData } from "../adapters/dexscreener.js";
import { erc20Meta } from "../adapters/rpc.js";
import { simulateHoneypot, type HoneypotResult } from "../sim/honeypot.js";
import { checkHoneypotIs, type HoneypotIsResult } from "../adapters/honeypotis.js";
import { getDeployerInfo, type DeployerInfo } from "../adapters/deployer.js";
import { analyzeClusters, type ClusterAnalysis } from "./cluster.js";
import { trackInsiderFlow, type InsiderFlow } from "./insiderflow.js";
import { scanTokenBytecode, type BytecodeScan } from "./bytecode.js";
import * as okx from "../adapters/okx.js";

/** Raw data gathered ONCE per verdict and shared across all dimension scorers (pure functions). */
export type RawContext = {
  chain: ChainKey;
  address: string;
  goplus: { data: GoPlusTokenSecurity | null; ok: boolean; error?: string; observed_at: string };
  market: MarketData;
  sim: HoneypotResult | null;
  meta: Awaited<ReturnType<typeof erc20Meta>> | null;
  hpis: HoneypotIsResult | null; // honeypot.is corroboration (contract-logic honeypot check)
  bytecode: BytecodeScan | null; // trap-selector scan of runtime bytecode (works on unverified contracts)
  deployer: DeployerInfo | null; // deployer/creator forensics
  insiderCluster: ClusterAnalysis | null; // self-computed insider/sybil cluster analysis (Magic-Nodes equivalent)
  insiderFlow: InsiderFlow | null; // are the deployer/insiders distributing (exit-in-progress)?
  // OKX Onchain OS data (null unless OKX API creds configured)
  okx: { cluster: any; signals: any; memepump: any; advanced: any } | null;
  // derived
  established: boolean;
  holderCount: number;
  symbol?: string;
  name?: string;
};

const yes = (v: any) => v === "1" || v === 1 || v === true;

export async function gather(chain: ChainKey, address: string, opts: { sim: boolean }): Promise<RawContext> {
  const addr = address.toLowerCase() as `0x${string}`;
  const okxConfigured = okx.isConfigured();
  const [goplus, market, meta, sim, hpis, bytecode, okxData] = await Promise.all([
    getTokenSecurity(chain, address),
    getMarket(chain, address),
    erc20Meta(chain, addr).catch(() => null),
    opts.sim ? simulateHoneypot(chain, addr).catch((): HoneypotResult | null => null) : Promise.resolve(null),
    checkHoneypotIs(chain, address).catch((): HoneypotIsResult | null => null),
    scanTokenBytecode(chain, addr).catch((): BytecodeScan | null => null),
    okxConfigured
      ? Promise.all([
          okx.getClusterOverview(chain, address).catch(() => ({ data: null })),
          okx.getSignals(chain, address).catch(() => ({ data: null })),
          okx.getMemepumpToken(chain, address).catch(() => ({ data: null })),
          okx.getAdvancedInfo(chain, address).catch(() => ({ data: null })),
        ]).then(([cluster, signals, memepump, advanced]) => ({ cluster: cluster.data, signals: signals.data, memepump: memepump.data, advanced: advanced.data }))
      : Promise.resolve(null),
  ]);

  const g = goplus.data ?? {};
  // deployer forensics + insider-cluster both need the creator/holders from GoPlus → run after the batch.
  // Cluster analysis is ~30 RPC calls, so it only runs on the full/deep tier (opts.sim), never flag.
  const BURN = new Set(["0x000000000000000000000000000000000000dead", "0x0000000000000000000000000000000000000000"]);
  const eoaHolders = (Array.isArray(g.holders) ? g.holders : [])
    .filter((h: any) => !(h.is_contract === "1" || h.is_contract === 1 || h.is_locked === true || h.is_locked === "1" || BURN.has((h.address || "").toLowerCase())))
    .map((h: any) => ({ address: (h.address || "").toLowerCase(), percent: parseFloat(h.percent) || 0 }));
  const [deployer, insiderCluster] = await Promise.all([
    getDeployerInfo(chain, g.creator_address).catch((): DeployerInfo | null => null),
    opts.sim && eoaHolders.length >= 2
      ? analyzeClusters(chain, addr, eoaHolders, g.creator_address).catch((): ClusterAnalysis | null => null)
      : Promise.resolve(null),
  ]);
  const holderCount = parseInt(g.holder_count ?? "0", 10) || 0;
  const inCex = yes(g.is_in_cex) || (g.is_in_cex && g.is_in_cex.listed === "1");
  const established = yes(g.trust_list) || !!inCex || holderCount > 50_000;

  // insider distribution: track the deployer + any detected cluster members for token outflow (exit-in-progress).
  // Skipped for established tokens (their deployer wallets are long dormant / irrelevant).
  const insiderWallets = [
    ...(g.creator_address ? [String(g.creator_address)] : []),
    ...(insiderCluster?.clusters.flatMap((c) => c.members) ?? []),
  ];
  const insiderFlow = opts.sim && insiderWallets.length > 0 && !established
    ? await trackInsiderFlow(chain, addr, insiderWallets).catch((): InsiderFlow | null => null)
    : null;

  return {
    chain, address, goplus, market, sim, meta, hpis, bytecode, deployer, insiderCluster, insiderFlow,
    okx: okxData,
    established, holderCount,
    symbol: g.token_symbol || g.symbol || meta?.symbol,
    name: g.token_name || meta?.name,
  };
}
