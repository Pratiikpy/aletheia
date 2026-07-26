import type { ChainKey } from "../config.js";

/** honeypot.is — free, keyless. Contract-logic honeypot check (catches traps even with no live liquidity). */

const CHAIN_ID: Partial<Record<ChainKey, number>> = { ethereum: 1, bsc: 56, base: 8453 };

export type HoneypotIsResult = {
  ok: boolean;
  observed_at: string;
  isHoneypot: boolean | null;
  buyTax: number | null;
  sellTax: number | null;
  risk: string | null;
  flags: string[];
  error?: string;
};

export async function checkHoneypotIs(chain: ChainKey, address: string): Promise<HoneypotIsResult> {
  const observed_at = new Date().toISOString();
  const id = CHAIN_ID[chain];
  if (!id) return { ok: false, observed_at, isHoneypot: null, buyTax: null, sellTax: null, risk: null, flags: [], error: `honeypot.is unsupported chain ${chain}` };
  try {
    const res = await fetch(`https://api.honeypot.is/v2/IsHoneypot?address=${address}&chainID=${id}`, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(30_000) });
    const j: any = await res.json();
    const sim = j?.simulationResult ?? {};
    return {
      ok: true, observed_at,
      isHoneypot: j?.honeypotResult?.isHoneypot ?? null,
      buyTax: sim.buyTax != null ? Number(sim.buyTax) / 100 : null,
      sellTax: sim.sellTax != null ? Number(sim.sellTax) / 100 : null,
      risk: j?.summary?.risk ?? j?.summary?.riskLevel ?? null,
      flags: Array.isArray(j?.summary?.flags) ? j.summary.flags.map((f: any) => f.flag ?? f) : [],
    };
  } catch (e: any) {
    return { ok: false, observed_at, isHoneypot: null, buyTax: null, sellTax: null, risk: null, flags: [], error: e?.message ?? String(e) };
  }
}
