import type { ChainKey } from "../config.js";
import { buildTrades, toLegs, foldStableQuotes, type Trade } from "./pnl.js";
import { alchemyRpc, CHAINS } from "../config.js";
import { getMarket } from "../adapters/dexscreener.js";

/**
 * Crypto tax engine — a realized gain/loss report from the reconstructed on-chain trade ledger.
 *
 * Same FIFO cost-basis machinery as the PnL engine, but emitting per-disposal tax lots: proceeds,
 * cost basis, gain/loss, and holding period (short vs long) for every sell. Denominated in the chain's
 * native asset (users apply their own fiat rates / jurisdiction rules) — honest about what it is. This
 * is the "export my trades for taxes" surface, self-computed and free; no paid tax API.
 */

const WRAPPED: Partial<Record<ChainKey, string>> = {
  ethereum: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
  bsc: "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
  base: "0x4200000000000000000000000000000000000006",
  arbitrum: "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
  polygon: "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
};
const LONG_TERM_DAYS = 365;

export type TaxLot = {
  token: string;
  proceeds: number; // native received on the sale
  costBasis: number; // native cost of the disposed amount (FIFO)
  gain: number; // proceeds - costBasis
  amount: number; // token amount disposed
  acquiredTs: number; // unix seconds of the acquiring buy (FIFO lot)
  disposedTs: number; // unix seconds of the sale
  holdingDays: number;
  term: "short" | "long";
};

export type TaxReport = {
  ok: boolean;
  observed_at: string;
  wallet: string;
  chain: ChainKey;
  nativeSymbol: string;
  year: number | null;
  disposals: number;
  proceeds: number;
  costBasis: number;
  realizedGain: number; // total native gain/loss
  shortTermGain: number;
  longTermGain: number;
  lots: TaxLot[];
  note: string;
  error?: string;
};

/** Compute FIFO tax lots from an ordered trade list (pure, unit-testable). */
export function computeTaxLots(trades: Trade[], opts: { year?: number } = {}): TaxLot[] {
  const byToken = new Map<string, Trade[]>();
  for (const t of trades) { if (!byToken.has(t.token)) byToken.set(t.token, []); byToken.get(t.token)!.push(t); }
  const lots: TaxLot[] = [];
  for (const [token, ts] of byToken) {
    const open: { amount: number; unitCost: number; ts: number }[] = [];
    for (const t of ts) {
      if (t.side === "buy") {
        open.push({ amount: t.tokenAmount, unitCost: t.quoteNative / t.tokenAmount, ts: t.ts });
      } else {
        const unitProceeds = t.quoteNative / t.tokenAmount;
        let toSell = t.tokenAmount;
        while (toSell > 1e-18 && open.length) {
          const lot = open[0]!;
          const take = Math.min(toSell, lot.amount);
          const proceeds = take * unitProceeds;
          const costBasis = take * lot.unitCost;
          const holdingDays = Math.max(0, (t.ts - lot.ts) / 86400);
          lots.push({
            token, proceeds, costBasis, gain: proceeds - costBasis, amount: take,
            acquiredTs: lot.ts, disposedTs: t.ts, holdingDays,
            term: holdingDays >= LONG_TERM_DAYS ? "long" : "short",
          });
          lot.amount -= take; toSell -= take;
          if (lot.amount <= 1e-18) open.shift();
        }
        // disposal with no basis (received/airdropped) → full proceeds as gain, zero basis
        if (toSell > 1e-18) {
          const proceeds = toSell * unitProceeds;
          lots.push({ token, proceeds, costBasis: 0, gain: proceeds, amount: toSell, acquiredTs: t.ts, disposedTs: t.ts, holdingDays: 0, term: "short" });
        }
      }
    }
  }
  const filtered = opts.year != null ? lots.filter((l) => new Date(l.disposedTs * 1000).getUTCFullYear() === opts.year) : lots;
  return filtered.sort((a, b) => a.disposedTs - b.disposedTs);
}

async function rpc(chain: ChainKey, method: string, params: any[]): Promise<any> {
  const res = await fetch(alchemyRpc(chain), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(30_000) });
  const j: any = await res.json();
  if (j.error) throw new Error(j.error.message ?? "rpc error");
  return j.result;
}
async function getAssetTransfers(chain: ChainKey, dir: "from" | "to", wallet: string): Promise<any[]> {
  const key = dir === "from" ? "fromAddress" : "toAddress";
  const out: any[] = []; let pageKey: string | undefined;
  for (let i = 0; i < 3; i++) {
    const params: any = { [key]: wallet, category: ["external", "internal", "erc20"], order: "asc", maxCount: "0x3e8", withMetadata: true, excludeZeroValue: true };
    if (pageKey) params.pageKey = pageKey;
    const r = await rpc(chain, "alchemy_getAssetTransfers", [params]).catch(() => null);
    if (!r?.transfers) break;
    out.push(...r.transfers);
    if (!r.pageKey) break; pageKey = r.pageKey;
  }
  return out;
}

const CHAINS_WITH_TRANSFERS = new Set<ChainKey>(["ethereum", "bsc", "base", "arbitrum", "polygon"]);
const NATIVE_SYMBOL: Record<string, string> = { ethereum: "ETH", bsc: "BNB", base: "ETH", arbitrum: "ETH", polygon: "MATIC" };

export async function taxReport(chain: ChainKey, wallet: string, opts: { year?: number } = {}): Promise<TaxReport> {
  const observed_at = new Date().toISOString();
  const nativeSymbol = NATIVE_SYMBOL[chain] ?? "ETH";
  const base: TaxReport = { ok: false, observed_at, wallet, chain, nativeSymbol, year: opts.year ?? null, disposals: 0, proceeds: 0, costBasis: 0, realizedGain: 0, shortTermGain: 0, longTermGain: 0, lots: [], note: "" };
  if (!CHAINS_WITH_TRANSFERS.has(chain)) return { ...base, error: "transfer history unavailable on this chain" };
  if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return { ...base, error: "invalid wallet address" };
  const w = wallet.toLowerCase();
  try {
    const [outRaw, inRaw] = await Promise.all([getAssetTransfers(chain, "from", w), getAssetTransfers(chain, "to", w)]);
    let trades = buildTrades([...toLegs(outRaw, "out", w), ...toLegs(inRaw, "in", w)], chain);
    if (trades.some((t) => t.quoteStableUsd > 0)) {
      const wrapped = WRAPPED[chain];
      const px = wrapped ? (await getMarket(chain, wrapped).catch(() => null))?.topPair?.priceUsd ?? 0 : 0;
      trades = foldStableQuotes(trades, px || 1);
    }
    const lots = computeTaxLots(trades, { year: opts.year });
    const proceeds = lots.reduce((s, l) => s + l.proceeds, 0);
    const costBasis = lots.reduce((s, l) => s + l.costBasis, 0);
    const shortTermGain = lots.filter((l) => l.term === "short").reduce((s, l) => s + l.gain, 0);
    const longTermGain = lots.filter((l) => l.term === "long").reduce((s, l) => s + l.gain, 0);
    return {
      ok: true, observed_at, wallet: w, chain, nativeSymbol, year: opts.year ?? null,
      disposals: lots.length, proceeds, costBasis, realizedGain: proceeds - costBasis, shortTermGain, longTermGain,
      lots: lots.slice(0, 500),
      note: `Realized gains are denominated in ${nativeSymbol}. Apply your own fiat conversion rates and local tax rules. FIFO cost basis; long-term = held ≥ ${LONG_TERM_DAYS} days.`,
    };
  } catch (e: any) {
    return { ...base, wallet: w, error: e?.message ?? String(e) };
  }
}
