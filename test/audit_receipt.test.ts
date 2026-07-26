import { describe, it, expect } from "vitest";
import { paidRouteInfo } from "../src/api/okxpay.js";

/**
 * The one number on a receipt that must never be guessed.
 *
 * `/audit` reports a `cost` block to the buyer. It was a hardcoded "0.90" while the registered fee is
 * 0.05 USDT — every audit receipt overstated what was actually charged by 18x. It is now read from the
 * same ROUTES table the paywall charges from, so the two cannot drift apart again.
 */
describe("audit receipt cost", () => {
  it("matches the fee the paywall actually charges", () => {
    const info = paidRouteInfo("/audit");
    expect(info).not.toBeNull();
    expect(info!.fee).toBe("0.05");
  });

  it("exposes a fee for every registered paid route", () => {
    for (const path of ["/verdict", "/audit", "/dyor", "/ask", "/research", "/report"]) {
      const info = paidRouteInfo(path);
      expect(info, `no route info for ${path}`).not.toBeNull();
      expect(Number(info!.fee), `fee for ${path} must be a positive number`).toBeGreaterThan(0);
    }
  });
});
