import { alchemyRpc, CHAINS, type ChainKey } from "../config.js";
import { getMarket } from "../adapters/dexscreener.js";

/**
 * Wallet realized-PnL & win-rate compute — the engine behind smart-money scoring and copy-intelligence.
 *
 * Fully self-computed from free Alchemy asset-transfer history — no paid analytics API. Method:
 *   1. Pull every transfer leg touching the wallet (native + internal + ERC-20), both directions.
 *   2. Group legs by transaction; within a tx, net the wallet's delta per asset.
 *   3. A tx where the wallet gains a token and loses the quote asset (ETH/WETH/stable) is a BUY;
 *      the opposite is a SELL. The quote leg is the price paid/received.
 *   4. FIFO cost-basis per token → realized PnL; subtract real gas (receipt gasUsed × effectiveGasPrice).
 *   5. Win-rate = share of fully/partially realized tokens whose realized PnL is positive.
 *
 * PnL is denominated in the chain's native asset (ETH/BNB/…). Stable-quoted legs are converted at the
 * CURRENT native price (documented approximation); native-quoted trades — the vast majority of memecoin
 * activity where this signal matters — are exact. Deterministic given the same on-chain history.
 */

const WRAPPED: Partial<Record<ChainKey, string>> = {
  ethereum: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
  bsc: "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
  base: "0x4200000000000000000000000000000000000006",
  arbitrum: "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
  polygon: "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
};
const STABLES: Record<string, number> = {
  // address -> usd unit value (all ≈ $1)
  "0xdac17f958d2ee523a2206206994597c13d831ec7": 1, // USDT eth
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 1, // USDC eth
  "0x6b175474e89094c44da98b954eedeac495271d0f": 1, // DAI eth
  "0x55d398326f99059ff775485246999027b3197955": 1, // USDT bsc
  "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": 1, // USDC bsc
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": 1, // USDC base
  "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": 1, // USDT arb
  "0xaf88d065e77c8cc2239327c5edb3a432268e5831": 1, // USDC arb
  "0xc2132d05d31c914a87c6611c10748aeb04b58e8f": 1, // USDT polygon
  "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": 1, // USDC polygon
};

export type TransferLeg = {
  hash: string;
  block: number;
  ts: number; // unix seconds
  asset: string; // token contract (lowercased) or "native"
  direction: "in" | "out";
  amount: number; // decimal units
};

export type Trade = {
  hash: string;
  block: number;
  ts: number;
  token: string; // the non-quote asset traded
  side: "buy" | "sell";
  tokenAmount: number;
  quoteNative: number; // native-asset amount on the quote leg (ETH/BNB/wrapped)
  quoteStableUsd: number; // stablecoin USD amount on the quote leg (folded into native once price is known)
};

export type TokenPnl = {
  token: string;
  realizedNative: number; // FIFO realized PnL in native units (gas not yet applied at token level)
  buys: number;
  sells: number;
  tokenBought: number;
  tokenSold: number;
  remaining: number; // unsold token amount (open position)
};

export type WalletPnl = {
  ok: boolean;
  observed_at: string;
  wallet: string;
  chain: ChainKey;
  nativeSymbol: string;
  tradeCount: number;
  tokensTraded: number;
  realizedNative: number; // total realized PnL across tokens (before gas)
  gasNative: number; // total gas spent on trade txns
  netNative: number; // realizedNative - gasNative
  winRate: number | null; // 0..1 over tokens with any realized (sold) volume; null if none realized
  realizedTokens: number; // # tokens with sold volume (denominator of winRate)
  winners: number;
  perToken: TokenPnl[]; // sorted by |realizedNative| desc
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

async function getAssetTransfers(chain: ChainKey, dir: "from" | "to", wallet: string, maxPages = 3): Promise<any[]> {
  const key = dir === "from" ? "fromAddress" : "toAddress";
  const out: any[] = [];
  let pageKey: string | undefined;
  for (let i = 0; i < maxPages; i++) {
    const params: any = {
      [key]: wallet,
      category: ["external", "internal", "erc20"],
      order: "asc",
      maxCount: "0x3e8", // 1000
      withMetadata: true,
      excludeZeroValue: true,
    };
    if (pageKey) params.pageKey = pageKey;
    const r = await rpc(chain, "alchemy_getAssetTransfers", [params]).catch(() => null);
    if (!r?.transfers) break;
    out.push(...r.transfers);
    if (!r.pageKey) break;
    pageKey = r.pageKey;
  }
  return out;
}

/** Convert raw Alchemy transfers (both directions) into normalized legs from the wallet's POV. */
export function toLegs(raw: any[], direction: "in" | "out", wallet: string): TransferLeg[] {
  const w = wallet.toLowerCase();
  const legs: TransferLeg[] = [];
  for (const t of raw) {
    const value = typeof t.value === "number" ? t.value : parseFloat(t.value);
    if (!value || Number.isNaN(value)) continue;
    // native (ETH/BNB…) shows as category external/internal with rawContract.address null and asset the chain symbol
    const contract = t.rawContract?.address ? String(t.rawContract.address).toLowerCase() : null;
    const asset = t.category === "erc20" && contract ? contract : "native";
    const ts = t.metadata?.blockTimestamp ? Math.floor(new Date(t.metadata.blockTimestamp).getTime() / 1000) : 0;
    // guard: only keep legs where the wallet is the stated party for this direction
    const from = String(t.from || "").toLowerCase();
    const to = String(t.to || "").toLowerCase();
    if (direction === "out" && from !== w) continue;
    if (direction === "in" && to !== w) continue;
    legs.push({ hash: t.hash, block: t.blockNum ? parseInt(t.blockNum, 16) : 0, ts, asset, direction, amount: value });
  }
  return legs;
}

/** Group legs by tx and classify each swap-like tx into a Trade (pure, testable). */
export function buildTrades(legs: TransferLeg[], chain: ChainKey): Trade[] {
  const wrapped = WRAPPED[chain];
  const isQuote = (a: string) => a === "native" || a === wrapped || a in STABLES;
  const byTx = new Map<string, TransferLeg[]>();
  for (const l of legs) {
    if (!byTx.has(l.hash)) byTx.set(l.hash, []);
    byTx.get(l.hash)!.push(l);
  }
  const trades: Trade[] = [];
  for (const [hash, ls] of byTx) {
    // net delta per asset within this tx
    const delta = new Map<string, number>();
    for (const l of ls) delta.set(l.asset, (delta.get(l.asset) ?? 0) + (l.direction === "in" ? l.amount : -l.amount));
    // split the quote side into native (ETH/wrapped) vs stablecoin (USD) so we can price them correctly
    let nativeDelta = 0, stableDelta = 0;
    for (const [a, d] of delta) {
      if (a === "native" || a === wrapped) nativeDelta += d;
      else if (a in STABLES) stableDelta += d * STABLES[a]!;
    }
    const quoteSign = nativeDelta + stableDelta; // sign only — direction of value flow
    // find the single non-quote token with the largest |delta| → the token being traded
    let token: string | null = null;
    let tokenDelta = 0;
    for (const [a, d] of delta) {
      if (isQuote(a)) continue;
      if (Math.abs(d) > Math.abs(tokenDelta)) { token = a; tokenDelta = d; }
    }
    if (!token || tokenDelta === 0 || quoteSign === 0) continue;
    const l0 = ls[0]!;
    // token gained + quote lost = BUY ; token lost + quote gained = SELL
    if (tokenDelta > 0 && quoteSign < 0) {
      trades.push({ hash, block: l0.block, ts: l0.ts, token, side: "buy", tokenAmount: tokenDelta, quoteNative: Math.abs(nativeDelta), quoteStableUsd: Math.abs(stableDelta) });
    } else if (tokenDelta < 0 && quoteSign > 0) {
      trades.push({ hash, block: l0.block, ts: l0.ts, token, side: "sell", tokenAmount: Math.abs(tokenDelta), quoteNative: Math.abs(nativeDelta), quoteStableUsd: Math.abs(stableDelta) });
    }
  }
  trades.sort((a, b) => a.block - b.block || a.ts - b.ts);
  return trades;
}

/** Fold each trade's stablecoin quote leg into native units at the given native/USD price (pure). */
export function foldStableQuotes(trades: Trade[], nativePriceUsd: number): Trade[] {
  const px = nativePriceUsd > 0 ? nativePriceUsd : 1;
  return trades.map((t) => ({ ...t, quoteNative: t.quoteNative + t.quoteStableUsd / px, quoteStableUsd: 0 }));
}

/** FIFO realized PnL per token from an ordered trade list (pure, testable). */
export function computePnl(trades: Trade[]): { perToken: TokenPnl[]; realizedNative: number; winRate: number | null; realizedTokens: number; winners: number } {
  const byToken = new Map<string, Trade[]>();
  for (const t of trades) {
    if (!byToken.has(t.token)) byToken.set(t.token, []);
    byToken.get(t.token)!.push(t);
  }
  const perToken: TokenPnl[] = [];
  for (const [token, ts] of byToken) {
    // FIFO lots: each buy adds a lot {amount, unitCost}; each sell consumes lots and realizes PnL
    const lots: { amount: number; unitCost: number }[] = [];
    let realized = 0, buys = 0, sells = 0, tokenBought = 0, tokenSold = 0;
    for (const t of ts) {
      if (t.side === "buy") {
        buys++; tokenBought += t.tokenAmount;
        lots.push({ amount: t.tokenAmount, unitCost: t.quoteNative / t.tokenAmount });
      } else {
        sells++; tokenSold += t.tokenAmount;
        const unitProceeds = t.quoteNative / t.tokenAmount;
        let toSell = t.tokenAmount;
        while (toSell > 1e-18 && lots.length) {
          const lot = lots[0]!;
          const take = Math.min(toSell, lot.amount);
          realized += take * (unitProceeds - lot.unitCost);
          lot.amount -= take; toSell -= take;
          if (lot.amount <= 1e-18) lots.shift();
        }
        // selling with no cost basis (airdrop/received): count proceeds as pure gain
        if (toSell > 1e-18) realized += toSell * unitProceeds;
      }
    }
    const remaining = lots.reduce((s, l) => s + l.amount, 0);
    perToken.push({ token, realizedNative: realized, buys, sells, tokenBought, tokenSold, remaining });
  }
  perToken.sort((a, b) => Math.abs(b.realizedNative) - Math.abs(a.realizedNative));
  const realizedSet = perToken.filter((p) => p.tokenSold > 0);
  const winners = realizedSet.filter((p) => p.realizedNative > 0).length;
  const realizedNative = perToken.reduce((s, p) => s + p.realizedNative, 0);
  return {
    perToken,
    realizedNative,
    realizedTokens: realizedSet.length,
    winners,
    winRate: realizedSet.length ? winners / realizedSet.length : null,
  };
}

const CHAINS_WITH_TRANSFERS = new Set<ChainKey>(["ethereum", "bsc", "base", "arbitrum", "polygon"]);
const NATIVE_SYMBOL: Record<string, string> = { ethereum: "ETH", bsc: "BNB", base: "ETH", arbitrum: "ETH", polygon: "MATIC" };

/** End-to-end: fetch history, reconstruct trades, compute FIFO PnL + real gas, return the wallet scorecard. */
export async function walletPnl(chain: ChainKey, wallet: string, opts: { maxGasTxns?: number } = {}): Promise<WalletPnl> {
  const observed_at = new Date().toISOString();
  const nativeSymbol = NATIVE_SYMBOL[chain] ?? "ETH";
  if (!CHAINS_WITH_TRANSFERS.has(chain)) {
    return { ok: false, observed_at, wallet, chain, nativeSymbol, tradeCount: 0, tokensTraded: 0, realizedNative: 0, gasNative: 0, netNative: 0, winRate: null, realizedTokens: 0, winners: 0, perToken: [], error: "asset-transfer history unavailable on this chain" };
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
    return { ok: false, observed_at, wallet, chain, nativeSymbol, tradeCount: 0, tokensTraded: 0, realizedNative: 0, gasNative: 0, netNative: 0, winRate: null, realizedTokens: 0, winners: 0, perToken: [], error: "invalid wallet address" };
  }
  const w = wallet.toLowerCase();
  try {
    const [outRaw, inRaw] = await Promise.all([getAssetTransfers(chain, "from", w), getAssetTransfers(chain, "to", w)]);
    const legs = [...toLegs(outRaw, "out", w), ...toLegs(inRaw, "in", w)];
    let trades = buildTrades(legs, chain);

    // fold any stablecoin-quoted legs into native units at the current native price (native-quoted
    // trades are untouched); only fetch the price if at least one trade actually used a stable quote.
    if (trades.some((t) => t.quoteStableUsd > 0)) {
      const wrapped = WRAPPED[chain];
      const nativePriceUsd = wrapped ? (await getMarket(chain, wrapped).catch(() => null))?.topPair?.priceUsd ?? 0 : 0;
      trades = foldStableQuotes(trades, nativePriceUsd || 1);
    }

    const { perToken, realizedNative, winRate, realizedTokens, winners } = computePnl(trades);

    // real gas: sum receipts for the trade txns (bounded)
    const maxGas = opts.maxGasTxns ?? 120;
    const uniqTx = [...new Set(trades.map((t) => t.hash))].slice(0, maxGas);
    const receipts = await mapLimit(uniqTx, 8, (h) => rpc(chain, "eth_getTransactionReceipt", [h]).catch(() => null));
    let gasWei = 0n;
    for (const r of receipts) {
      if (!r?.gasUsed) continue;
      const gasUsed = BigInt(r.gasUsed);
      const price = BigInt(r.effectiveGasPrice ?? "0x0");
      // only the wallet's own txns cost it gas (sender == wallet)
      if (String(r.from || "").toLowerCase() === w) gasWei += gasUsed * price;
    }
    const gasNative = Number(gasWei) / 1e18;

    return {
      ok: true, observed_at, wallet: w, chain, nativeSymbol,
      tradeCount: trades.length,
      tokensTraded: perToken.length,
      realizedNative,
      gasNative,
      netNative: realizedNative - gasNative,
      winRate, realizedTokens, winners,
      perToken: perToken.slice(0, 25),
    };
  } catch (e: any) {
    return { ok: false, observed_at, wallet: w, chain, nativeSymbol, tradeCount: 0, tokensTraded: 0, realizedNative: 0, gasNative: 0, netNative: 0, winRate: null, realizedTokens: 0, winners: 0, perToken: [], error: e?.message ?? String(e) };
  }
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx]!); }
  }));
  return out;
}

export { CHAINS };
