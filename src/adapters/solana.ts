import { Connection, PublicKey } from "@solana/web3.js";
import { config } from "../config.js";

/**
 * Solana token intelligence adapter — the SPL-native equivalent of the EVM honeypot/security stack.
 *
 * Solana rugs look different from EVM ones, so the checks are different:
 *   - freeze authority set  → the issuer can freeze any holder's token account → they CANNOT sell.
 *                             This is the true Solana "honeypot": you buy, then get frozen out.
 *   - mint authority set    → supply can be inflated at will (dilution / infinite-mint rug).
 *   - Token-2022 extensions → transfer-fee (tax), transfer-hook (arbitrary sell-blocking program),
 *                             permanent-delegate (issuer can move/burn your tokens).
 *   - tradeability          → a live Jupiter route check: can the token actually be SOLD for USDC now?
 *
 * All keyless-ish: Helius RPC (mint + holders) + Jupiter public quote API (route/price-impact). Reproducible.
 */

const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SOL = "So11111111111111111111111111111111111111112";

let _conn: Connection | null = null;
function conn(): Connection {
  if (!_conn) _conn = new Connection(`https://mainnet.helius-rpc.com/?api-key=${config.heliusKey}`, "confirmed");
  return _conn;
}

export type SolMintInfo = {
  ok: boolean;
  observed_at: string;
  mint: string;
  isToken2022: boolean;
  decimals: number | null;
  supply: string | null;
  mintAuthority: string | null; // non-null → supply inflatable
  freezeAuthority: string | null; // non-null → holders can be frozen (Solana honeypot vector)
  extensions: string[]; // Token-2022 extension names present
  transferFeeBps: number | null; // current transfer fee (Token-2022), basis points
  hasTransferHook: boolean; // arbitrary program runs on transfer (can block sells)
  hasPermanentDelegate: boolean; // issuer can move/burn any holder's tokens
  error?: string;
};

export async function getSolMintInfo(mint: string): Promise<SolMintInfo> {
  const observed_at = new Date().toISOString();
  const base: SolMintInfo = {
    ok: false, observed_at, mint, isToken2022: false, decimals: null, supply: null,
    mintAuthority: null, freezeAuthority: null, extensions: [], transferFeeBps: null,
    hasTransferHook: false, hasPermanentDelegate: false,
  };
  let pk: PublicKey;
  try { pk = new PublicKey(mint); } catch { return { ...base, error: "invalid mint address" }; }
  try {
    const res = await conn().getParsedAccountInfo(pk);
    const val: any = res.value;
    if (!val) return { ...base, error: "mint account not found" };
    const program = typeof val.owner?.toBase58 === "function" ? val.owner.toBase58() : String(val.owner);
    const isToken2022 = program === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    const info = val.data?.parsed?.info ?? {};
    const extList: any[] = Array.isArray(info.extensions) ? info.extensions : [];
    const extNames = extList.map((e) => e.extension).filter(Boolean);

    // transfer-fee extension → current fee in bps
    const feeExt = extList.find((e) => e.extension === "transferFeeConfig");
    const newerFee = feeExt?.state?.newerTransferFee?.transferFeeBasisPoints;
    const olderFee = feeExt?.state?.olderTransferFee?.transferFeeBasisPoints;
    const transferFeeBps = newerFee != null ? Number(newerFee) : olderFee != null ? Number(olderFee) : null;

    return {
      ok: true, observed_at, mint,
      isToken2022,
      decimals: info.decimals ?? null,
      supply: info.supply ?? null,
      mintAuthority: info.mintAuthority ?? null,
      freezeAuthority: info.freezeAuthority ?? null,
      extensions: extNames,
      transferFeeBps,
      hasTransferHook: extNames.includes("transferHook"),
      hasPermanentDelegate: extNames.includes("permanentDelegate"),
    };
  } catch (e: any) {
    return { ...base, error: e?.message ?? String(e) };
  }
}

export type SolHolders = {
  ok: boolean;
  observed_at: string;
  topPct: number; // largest single account share of supply (0..1), excluding the mint itself
  top10Pct: number; // top-10 combined (0..1)
  holders: { address: string; pct: number }[];
  error?: string;
};

export async function getSolTopHolders(mint: string, supply: string | null, decimals: number | null): Promise<SolHolders> {
  const observed_at = new Date().toISOString();
  try {
    const pk = new PublicKey(mint);
    const res = await conn().getTokenLargestAccounts(pk);
    const total = supply != null ? Number(supply) : null;
    const list = res.value.map((a) => ({ address: a.address.toBase58(), amount: Number(a.amount) }));
    const holders = list.map((h) => ({ address: h.address, pct: total && total > 0 ? h.amount / total : 0 }));
    const topPct = holders[0]?.pct ?? 0;
    const top10Pct = holders.slice(0, 10).reduce((s, h) => s + h.pct, 0);
    return { ok: true, observed_at, topPct, top10Pct, holders };
  } catch (e: any) {
    return { ok: false, observed_at, topPct: 0, top10Pct: 0, holders: [], error: e?.message ?? String(e) };
  }
}

export type SolTradeability = {
  ok: boolean;
  observed_at: string;
  buyable: boolean; // SOL → token route exists
  sellable: boolean; // token → USDC route exists
  sellPriceImpactPct: number | null; // price impact on a modest sell
  isHoneypot: boolean; // buyable but NOT sellable → classic trap
  error?: string;
};

/** Jupiter public quote — can this token actually be bought and then sold right now? */
async function jupQuote(inputMint: string, outputMint: string, amount: string): Promise<any | null> {
  const url = `https://lite-api.jup.ag/swap/v1/quote?inputMint=${inputMint}&outputMint=${outputMint}&amount=${amount}&slippageBps=1500`;
  try {
    const res = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(30_000) });
    if (!res.ok) return null;
    const j: any = await res.json();
    if (j?.error || !j?.outAmount) return null;
    return j;
  } catch {
    return null;
  }
}

export async function getSolTradeability(mint: string, decimals: number | null): Promise<SolTradeability> {
  const observed_at = new Date().toISOString();
  try {
    // pick a quote asset distinct from the token itself (selling USDC→USDC is not a valid route)
    const quoteMint = mint === USDC ? SOL : USDC;
    const buyVia = mint === SOL ? USDC : SOL; // buy leg pays in a different asset than the token
    // buy leg: 0.05 of the pay-asset → token
    const buy = await jupQuote(buyVia, mint, String(Math.round(0.05 * 1e9)));
    const buyable = !!buy;
    // sell leg: sell the amount we'd receive (or a nominal 1 token unit) back to the quote asset
    const sellAmount = buy?.outAmount ?? (decimals != null ? String(10 ** decimals) : "1000000");
    const sell = await jupQuote(mint, quoteMint, sellAmount);
    const sellable = !!sell;
    const sellPriceImpactPct = sell?.priceImpactPct != null ? Number(sell.priceImpactPct) * 100 : null;
    return {
      ok: true, observed_at, buyable, sellable, sellPriceImpactPct,
      isHoneypot: buyable && !sellable,
    };
  } catch (e: any) {
    return { ok: false, observed_at, buyable: false, sellable: false, sellPriceImpactPct: null, isHoneypot: false, error: e?.message ?? String(e) };
  }
}
