import { alchemyRpc, type ChainKey } from "../config.js";

/**
 * Insider distribution tracker — the flow counterpart to the static cluster map.
 *
 * The cluster module answers "who holds the float?"; this answers "are they getting OUT?". A deployer or
 * insider cluster that is quietly sending its allocation to the DEX pair (selling) mid-rally is the single
 * highest-signal exit-in-progress pattern. We measure each insider wallet's token outflow to the market
 * (LP pair / router / other wallets) as a share of what it received, and roll up how much insider supply
 * is being distributed. Keyless (Alchemy transfer history), reproducible, and pairs with cluster findings.
 */

export type InsiderWalletFlow = {
  wallet: string;
  received: number; // total token amount ever received
  sentOut: number; // total token amount sent out (distribution)
  distributedPct: number; // sentOut / received (0..1) — how much of its bag it has offloaded
};

export type InsiderFlow = {
  ok: boolean;
  observed_at: string;
  walletsTracked: number;
  activelyDistributing: number; // # insiders that have sent out >20% of received
  worstDistributedPct: number; // max single-wallet distributed share
  aggregateDistributedPct: number; // sentOut / received across all tracked insiders
  wallets: InsiderWalletFlow[];
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

/** Sum this wallet's token transfers in and out for a specific token. */
async function tokenFlow(chain: ChainKey, token: string, wallet: string): Promise<{ received: number; sentOut: number }> {
  const [inR, outR] = await Promise.all([
    rpc(chain, "alchemy_getAssetTransfers", [{ toAddress: wallet, contractAddresses: [token], category: ["erc20"], maxCount: "0x64", order: "asc" }]).catch(() => null),
    rpc(chain, "alchemy_getAssetTransfers", [{ fromAddress: wallet, contractAddresses: [token], category: ["erc20"], maxCount: "0x64", order: "asc" }]).catch(() => null),
  ]);
  const sum = (r: any) => (r?.transfers ?? []).reduce((s: number, t: any) => s + (typeof t.value === "number" ? t.value : parseFloat(t.value) || 0), 0);
  return { received: sum(inR), sentOut: sum(outR) };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx]!); }
  }));
  return out;
}

/** Pure roll-up of per-wallet flows into the insider-distribution summary (unit-testable). */
export function summarizeFlow(flows: InsiderWalletFlow[]): Pick<InsiderFlow, "activelyDistributing" | "worstDistributedPct" | "aggregateDistributedPct"> {
  const activelyDistributing = flows.filter((f) => f.distributedPct > 0.2).length;
  const worstDistributedPct = flows.reduce((mx, f) => Math.max(mx, f.distributedPct), 0);
  const totalRecv = flows.reduce((s, f) => s + f.received, 0);
  const totalSent = flows.reduce((s, f) => s + Math.min(f.sentOut, f.received), 0); // cap per-wallet at received
  return {
    activelyDistributing,
    worstDistributedPct,
    aggregateDistributedPct: totalRecv > 0 ? totalSent / totalRecv : 0,
  };
}

const CHAINS_WITH_TRANSFERS = new Set<ChainKey>(["ethereum", "bsc", "base", "arbitrum", "polygon"]);

/** Track token distribution across a set of insider wallets (deployer + cluster members). */
export async function trackInsiderFlow(chain: ChainKey, token: string, insiderWallets: string[]): Promise<InsiderFlow> {
  const observed_at = new Date().toISOString();
  const uniq = [...new Set(insiderWallets.map((w) => w.toLowerCase()).filter((w) => /^0x[a-fA-F0-9]{40}$/.test(w)))].slice(0, 15);
  if (!CHAINS_WITH_TRANSFERS.has(chain) || uniq.length === 0) {
    return { ok: false, observed_at, walletsTracked: 0, activelyDistributing: 0, worstDistributedPct: 0, aggregateDistributedPct: 0, wallets: [], error: uniq.length === 0 ? "no insider wallets" : "transfer history unavailable on this chain" };
  }
  try {
    const wallets: InsiderWalletFlow[] = await mapLimit(uniq, 6, async (wallet) => {
      const { received, sentOut } = await tokenFlow(chain, token.toLowerCase(), wallet);
      return { wallet, received, sentOut, distributedPct: received > 0 ? Math.min(1, sentOut / received) : 0 };
    });
    return { ok: true, observed_at, walletsTracked: wallets.length, ...summarizeFlow(wallets), wallets };
  } catch (e: any) {
    return { ok: false, observed_at, walletsTracked: 0, activelyDistributing: 0, worstDistributedPct: 0, aggregateDistributedPct: 0, wallets: [], error: e?.message ?? String(e) };
  }
}
