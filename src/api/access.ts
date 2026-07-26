import { timingSafeEqual } from "node:crypto";

/**
 * The ONLY unpaid bypass for a paid Aletheia endpoint: a server-only shared secret presented in the
 * `x-aletheia-internal` header (used by Aletheia's own A2A daemon to fulfil a task the client already
 * paid for via escrow). Constant-time compared.
 *
 * Browser-forgeable headers (Sec-Fetch-Site / Origin / Referer / Host) are deliberately NOT accepted:
 * any HTTP client can set them, so trusting them would let an agent or the OKX marketplace validator
 * take the paid result for free — a non-compliant x402 endpoint and a direct rejection cause. This is
 * pure + exported so the "forged headers cannot bypass payment" guarantee is unit-locked without a
 * live facilitator.
 */
export function grantsInternalAccess(
  getHeader: (name: string) => string,
  internalSecret: string = process.env.ALETHEIA_INTERNAL_SECRET || "",
): boolean {
  const presented = getHeader("x-aletheia-internal") || "";
  if (internalSecret.length === 0 || presented.length !== internalSecret.length) return false;
  try {
    return timingSafeEqual(Buffer.from(internalSecret), Buffer.from(presented));
  } catch {
    return false;
  }
}
