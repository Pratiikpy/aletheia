/**
 * x402 (OKX Agent Payments) challenge helpers — spec-correct, self-implementable form.
 *
 * The marketplace validates a paid A2MCP endpoint by the x402 rule (OKX docs): an unpaid call must
 * return HTTP 402 with a standard payment challenge, and the resource is served only after a paid
 * replay. The official OKX Payment SDK builds that challenge for us in okxpay.ts; these pure helpers
 * are the same amount/asset/tier math in isolation, so pricing is a single source of truth and is
 * unit-testable without a live facilitator (and reusable if we ever self-implement the 402, which
 * the OKX docs explicitly allow).
 */

/** X Layer mainnet — the only network OKX x402 settles on. */
export const NETWORK = "eip155:196" as const;

/**
 * USD₮0 on X Layer — the settlement asset. `decimals` MUST be declared on each accepts entry: USD₮0
 * is not in OKX's built-in token list, so without it the facilitator cannot resolve the price
 * (the `tokenResolveError: cannot determine token decimals` rejection).
 */
export const USDT0 = {
  asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
  name: "USD₮0",
  version: "1",
  decimals: 6,
} as const;

/**
 * Canonical per-tier USD price for the token-verdict service — SINGLE SOURCE OF TRUTH.
 * verdict.ts derives its cost envelope from this, so the listed/charged price can never drift.
 */
export const TIER_USD: Record<"flag" | "full" | "deep", string> = {
  flag: "0.01",
  full: "0.02",
  deep: "0.05",
};

export const MAX_TIMEOUT_SECONDS = 300;

/** Convert a USD decimal string to atomic token units EXACTLY (BigInt — no float drift). */
export function toAtomic(usd: string, decimals: number): string {
  const s = String(usd).trim().replace(/^\$/, "");
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`invalid amount: ${usd}`);
  const [whole, frac = ""] = s.split(".");
  if (frac.length > decimals) throw new Error(`amount ${usd} exceeds ${decimals} decimals`);
  const fracPadded = (frac + "0".repeat(decimals)).slice(0, decimals);
  return (BigInt(whole || "0") * 10n ** BigInt(decimals) + BigInt(fracPadded || "0")).toString();
}

export type Accepts = {
  scheme: "exact";
  network: typeof NETWORK;
  maxAmountRequired: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  resource: string;
  extra: { name: string; version: string; decimals: number };
};

/** Resolve the seller payout address from env (never hard-coded); zero address if unset. */
export function payToAddress(): string {
  return process.env.X402_PAY_TO || process.env.OKX_PAY_TO || "0x0000000000000000000000000000000000000000";
}

/** Build a spec-shaped `exact` / EIP-3009 accepts entry for a token-verdict tier. */
export function buildAccepts(tier: "flag" | "full" | "deep", resource: string): Accepts {
  const usd = TIER_USD[tier] ?? TIER_USD.full;
  return {
    scheme: "exact",
    network: NETWORK,
    maxAmountRequired: toAtomic(usd, USDT0.decimals),
    asset: USDT0.asset,
    payTo: payToAddress(),
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    resource,
    extra: { name: USDT0.name, version: USDT0.version, decimals: USDT0.decimals },
  };
}
