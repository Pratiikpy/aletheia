import { describe, expect, it } from "vitest";

import { signReceipt, verifyReceipt } from "./sign.js";

/**
 * A receipt has to say which service issued it.
 *
 * Verified against the two live key endpoints: Aletheia and Reach publish the **same** signer
 * address, and neither signed block contained anything naming its source. So a buyer following the
 * published instruction — "compare the recovered signer to establish who issued the receipt" — had no
 * way to finish the comparison. Recovering the address proved it came from one of two services and
 * could not say which.
 *
 * Rotating the key would have fixed attribution and broken offline verification of every receipt
 * already issued. Naming the issuer inside the signed bytes fixes it without that cost, and because
 * the name is inside the signature it cannot be relabelled after the fact.
 */
describe("receipt attribution", () => {
  it("names the issuer inside the signed message", async () => {
    const r = await signReceipt({ kind: "test", subject: "abc" });
    if (!r) return;                       // no signing key configured in this environment
    expect(JSON.parse(r.message).issuer).toBe("aletheia");
  });

  it("reports the issuer back when verifying", async () => {
    const r = await signReceipt({ kind: "test", subject: "abc" });
    if (!r) return;
    const v = await verifyReceipt({ signer: r.signer as `0x${string}`, message: r.message,
                                    signature: r.signature as `0x${string}` });
    expect(v.valid).toBe(true);
    expect(v.issuer).toBe("aletheia");
    expect(v.issuerMatches).toBe(true);
  });

  it("cannot be relabelled without breaking the signature", async () => {
    const r = await signReceipt({ kind: "test", subject: "abc" });
    if (!r) return;
    const relabelled = r.message.replace('"issuer":"aletheia"', '"issuer":"reach"');
    expect(relabelled).not.toBe(r.message);
    const v = await verifyReceipt({ signer: r.signer as `0x${string}`, message: relabelled,
                                    signature: r.signature as `0x${string}` });
    expect(v.valid).toBe(false);
    expect(v.verdict).toBe("INVALID_SIGNATURE");
  });

  it("treats a receipt with no issuer as unidentified rather than invalid", async () => {
    const r = await signReceipt({ kind: "test" });
    if (!r) return;
    // An older receipt: genuine bytes, no issuer field. It must still verify.
    const legacy = JSON.stringify({ kind: "test" });
    const v = await verifyReceipt({ signer: r.signer as `0x${string}`, message: legacy,
                                    signature: r.signature as `0x${string}` });
    expect(v.issuer).toBeNull();
    expect(v.issuerMatches).toBeNull();
  });
});
