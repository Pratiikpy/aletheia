import type { ChainKey } from "../config.js";

/** DexScreener — free, keyless. Real market structure: price, liquidity, volume, pair age, txns. */

const CHAIN_SLUG: Record<ChainKey, string> = {
  ethereum: "ethereum",
  bsc: "bsc",
  base: "base",
  arbitrum: "arbitrum",
  polygon: "polygon",
  xlayer: "xlayer",
};

export type PairInfo = {
  dexId: string;
  priceUsd: number | null;
  liquidityUsd: number;
  volumeH24: number;
  volumeH1: number;
  priceChangeH24: number | null;
  pairCreatedAt: number | null; // ms epoch
  fdv: number | null;
  marketCap: number | null;
  txnsH24Buys: number;
  txnsH24Sells: number;
  url: string;
  baseSymbol?: string;
};

export type MarketData = {
  ok: boolean;
  observed_at: string;
  chain: ChainKey;
  address: string;
  pairs: PairInfo[];
  topPair: PairInfo | null;
  totalLiquidityUsd: number;
  error?: string;
};

export async function getMarket(chain: ChainKey, address: string): Promise<MarketData> {
  const observed_at = new Date().toISOString();
  const slug = CHAIN_SLUG[chain];
  try {
    const res = await fetch(`https://api.dexscreener.com/latest/dex/tokens/${address}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(30_000),
    });
    const json: any = await res.json();
    const raw: any[] = Array.isArray(json?.pairs) ? json.pairs : [];
    const pairs: PairInfo[] = raw
      .filter((p) => (p.chainId ?? "").toLowerCase() === slug)
      .map((p) => ({
        dexId: p.dexId,
        priceUsd: p.priceUsd != null ? Number(p.priceUsd) : null,
        liquidityUsd: Number(p.liquidity?.usd ?? 0),
        volumeH24: Number(p.volume?.h24 ?? 0),
        volumeH1: Number(p.volume?.h1 ?? 0),
        priceChangeH24: p.priceChange?.h24 != null ? Number(p.priceChange.h24) : null,
        pairCreatedAt: p.pairCreatedAt ?? null,
        fdv: p.fdv != null ? Number(p.fdv) : null,
        marketCap: p.marketCap != null ? Number(p.marketCap) : null,
        txnsH24Buys: Number(p.txns?.h24?.buys ?? 0),
        txnsH24Sells: Number(p.txns?.h24?.sells ?? 0),
        url: p.url,
        baseSymbol: p.baseToken?.symbol,
      }))
      .sort((a, b) => b.liquidityUsd - a.liquidityUsd);
    const totalLiquidityUsd = pairs.reduce((s, p) => s + p.liquidityUsd, 0);
    return { ok: pairs.length > 0, observed_at, chain, address, pairs, topPair: pairs[0] ?? null, totalLiquidityUsd, error: pairs.length ? undefined : "no pairs on DexScreener" };
  } catch (e: any) {
    return { ok: false, observed_at, chain, address, pairs: [], topPair: null, totalLiquidityUsd: 0, error: e?.message ?? String(e) };
  }
}
