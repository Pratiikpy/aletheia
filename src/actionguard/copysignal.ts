import type { ChainKey } from "../config.js";
import * as okx from "../adapters/okx.js";

/**
 * Copy-signal — "what is smart money doing on this token, right now?". Reads OKX Onchain OS smart-money
 * signals + the token's top profitable traders and returns a copy-worthiness read: are informed wallets
 * accumulating or distributing? Requires OKX creds (degrades to unavailable otherwise). Per-call ASP.
 */

export type CopySignal = {
  ok: boolean;
  observed_at: string;
  chain: ChainKey;
  token: string;
  verdict: "STRONG_ACCUMULATION" | "SMART_MONEY_BUYING" | "SOME_INTEREST" | "QUIET" | "UNAVAILABLE";
  signalCount: number; // buy-direction smart-money signals (OKX feed is buy-side only)
  topTraders: { address: string; realizedPnlUsd: number | null }[];
  summary: string;
  error?: string;
};

const num = (v: any): number | null => {
  if (v == null || v === "") return null;
  const n = typeof v === "string" ? parseFloat(v) : Number(v);
  return Number.isNaN(n) ? null : n;
};

/** Classify smart-money buy-interest strength (pure, testable). The OKX signal feed is buy-direction
 * only, so this measures accumulation interest, not distribution (which this feed cannot observe). */
export function classifyCopy(signalCount: number): CopySignal["verdict"] {
  if (signalCount >= 20) return "STRONG_ACCUMULATION";
  if (signalCount >= 8) return "SMART_MONEY_BUYING";
  if (signalCount >= 3) return "SOME_INTEREST";
  return "QUIET";
}

export async function copySignal(chain: ChainKey, token: string): Promise<CopySignal> {
  const observed_at = new Date().toISOString();
  const base = { ok: false, observed_at, chain, token, signalCount: 0, topTraders: [] as any[] };
  if (!okx.isConfigured()) return { ...base, verdict: "UNAVAILABLE", summary: "OKX API not configured — smart-money data unavailable.", error: "okx not configured" };
  try {
    const [sig, traders] = await Promise.all([okx.getSignals(chain, token), okx.getTopTraders(chain, token)]);
    // OKX /signal/list is a MARKET-WIDE latest-smart-money feed that ignores the token param, so we
    // filter it down to the queried token — otherwise every token would report the same global count.
    const rawList: any[] = Array.isArray(sig.data) ? sig.data : Array.isArray((sig.data as any)?.list) ? (sig.data as any).list : [];
    const tokenLc = token.toLowerCase();
    const list: any[] = rawList.filter((s: any) => String(s?.token?.tokenAddress ?? s?.tokenAddress ?? "").toLowerCase() === tokenLc);
    const tArr: any[] = Array.isArray(traders.data) ? traders.data : Array.isArray((traders.data as any)?.list) ? (traders.data as any).list : [];
    const topTraders = tArr.slice(0, 5).map((t) => ({
      address: t.holderWalletAddress ?? t.walletAddress ?? t.address ?? "",
      realizedPnlUsd: num(t.realizedProfit ?? t.totalPnl ?? t.pnl),
    })).filter((t) => t.address);
    const verdict = classifyCopy(list.length);
    const withPnl = topTraders.filter((t) => t.realizedPnlUsd != null);
    const profitClause = withPnl.length ? `; ${withPnl.filter((t) => (t.realizedPnlUsd as number) > 0).length}/${withPnl.length} top traders in profit` : topTraders.length ? `; ${topTraders.length} top traders identified` : "";
    const summary = verdict === "QUIET"
      ? "Little smart-money buy activity on this token."
      : `${list.length} recent smart-money buy signals${profitClause} — accumulation interest (note: OKX feed tracks buy-side only).`;
    return { ...base, ok: true, verdict, signalCount: list.length, topTraders, summary };
  } catch (e: any) {
    return { ...base, verdict: "UNAVAILABLE", summary: "Could not read smart-money data.", error: e?.message ?? String(e) };
  }
}
