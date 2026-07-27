import { privateKeyToAccount } from "viem/accounts";
import { keccak256, toHex, verifyMessage } from "viem";

/**
 * Self-proving receipts (Merit pattern): sign a verdict's canonical payload with Aletheia's key so any
 * caller can recover the signer OFFLINE and confirm the verdict without trusting our server — change
 * one field and the signature breaks. "Audit me, not trust me," made cryptographic.
 */

export type SignedReceipt = {
  signer: `0x${string}`;
  signature: `0x${string}`;
  message: string; // the exact canonical bytes that were signed
  digest: `0x${string}`; // keccak256 of the message, for convenience
  verify: string; // one-line instruction to check it offline
};

const PK = (process.env.EVM_WALLET_PRIVATE_KEY || "") as `0x${string}`;

/** Deterministic JSON with recursively sorted object keys — same bytes for anyone re-serializing. */
function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const keys = Object.keys(v as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify((v as Record<string, unknown>)[k])}`).join(",")}}`;
}

/** Sign a verdict payload. Returns null if no key is configured (caller omits `signed`). */
export async function signReceipt(payload: Record<string, unknown>): Promise<SignedReceipt | null> {
  if (!/^0x[a-fA-F0-9]{64}$/.test(PK)) return null;
  try {
    const account = privateKeyToAccount(PK);
    // The issuing service is named inside the signed bytes.
    //
    // This key is shared with a sibling ASP, so recovering the signer proves the receipt came from
    // one of them and cannot say which. Verified against both published key endpoints: Aletheia and
    // Reach advertise the identical address, and neither signed block carried anything naming its
    // source — so a buyer told to "compare the recovered signer to establish who issued this" had no
    // way to complete that comparison.
    //
    // Naming the service inside the payload fixes it without rotating the key, which matters: a new
    // key would invalidate offline verification of every receipt already issued. Old receipts stay
    // verifiable and simply lack the field; new ones are attributable.
    const message = stableStringify({ issuer: "aletheia", ...payload });
    const signature = await account.signMessage({ message });
    return {
      signer: account.address,
      signature,
      message,
      digest: keccak256(toHex(message)),
      verify: "Recover the signer offline: viem verifyMessage({ address: signer, message, signature }) === true. Any altered field breaks it.",
    };
  } catch {
    return null;
  }
}

/** Aletheia's own signing address — the trust anchor, published so a caller has something to
 *  compare a recovered signer against. A signature is only evidence of ORIGIN if you already know
 *  whose key to expect; without a published address it proves only that somebody signed something. */
export function signerAddress(): `0x${string}` | null {
  if (!/^0x[a-fA-F0-9]{64}$/.test(PK)) return null;
  try {
    return privateKeyToAccount(PK).address;
  } catch {
    return null;
  }
}

export type ReceiptVerification = {
  valid: boolean;             // signature is internally consistent with the claimed signer
  attributed: boolean | null; // ...and that signer really is Aletheia (null = no anchor configured)
  recoveredSigner: `0x${string}` | null;
  claimedSigner: string | null;
  expectedSigner: `0x${string}` | null;
  /** The service named inside the signed bytes. Null on receipts issued before the field existed. */
  issuer: string | null;
  /** Whether that name is this service. Null when the receipt carries no issuer to check. */
  issuerMatches: boolean | null;
  verdict: "VALID" | "VALID_SIGNATURE_UNKNOWN_ISSUER" | "VALID_UNATTRIBUTED" | "INVALID_SIGNATURE";
};

/**
 * Verify a receipt offline (used by the /receipt/verify convenience endpoint).
 *
 * Integrity and attribution are two different questions and this used to answer only the first while
 * reporting the second. `signer` arrives from the caller, so an attacker who signs a fabricated
 * verdict with their OWN key and names their own address passed the check — and the endpoint replied
 * "signed by Aletheia and unaltered". Every cryptographic step was sound; the identity was simply
 * never checked. The recovered signer is now compared against Aletheia's published address.
 */
export async function verifyReceipt(
  r: { signer: `0x${string}`; message: string; signature: `0x${string}`; expectedSigner?: string },
): Promise<ReceiptVerification> {
  const expected = ((r.expectedSigner || signerAddress() || "") as string).toLowerCase() || null;
  let recovered: `0x${string}` | null = null;
  let valid = false;
  try {
    valid = await verifyMessage({ address: r.signer, message: r.message, signature: r.signature });
    if (valid) recovered = r.signer;
  } catch {
    valid = false;
  }
  const attributed = expected && recovered ? recovered.toLowerCase() === expected : null;
  const verdict = !valid
    ? "INVALID_SIGNATURE"
    : attributed === false
      ? "VALID_SIGNATURE_UNKNOWN_ISSUER"
      : attributed === true
        ? "VALID"
        : "VALID_UNATTRIBUTED";
  // The signing key is shared with a sibling ASP, so the recovered address alone cannot say which of
  // them issued this. The issuer is named inside the signed bytes, which means reading it back is a
  // check and not a courtesy: an attacker cannot relabel it without invalidating the signature.
  // Receipts issued before the field existed report null rather than failing — they are still
  // genuine, just not self-identifying.
  let issuer: string | null = null;
  try {
    const parsed = JSON.parse(r.message);
    issuer = typeof parsed?.issuer === "string" ? parsed.issuer : null;
  } catch { issuer = null; }

  return {
    valid,
    attributed,
    recoveredSigner: recovered,
    claimedSigner: r.signer ?? null,
    expectedSigner: (expected as `0x${string}` | null),
    issuer,
    issuerMatches: issuer === null ? null : issuer === "aletheia",
    verdict,
  };
}
