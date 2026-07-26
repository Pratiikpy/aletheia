import crypto from "node:crypto";
import { config, CHAINS, type ChainKey } from "../config.js";

/**
 * GoPlus Token Security adapter — free breadth of contract-security fields.
 * Basic endpoint works keyless (rate-limited); we attach an access token for higher limits.
 */

let cachedToken: { token: string; expires: number } | null = null;

/** GoPlus access token: sign = sha1(app_key + time + app_secret). */
async function getAccessToken(): Promise<string | null> {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.expires > now + 60) return cachedToken.token;
  try {
    const time = now;
    const sign = crypto
      .createHash("sha1")
      .update(`${config.goplus.appKey}${time}${config.goplus.appSecret}`)
      .digest("hex");
    const res = await fetch(`${config.goplus.baseUrl}/api/v1/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ app_key: config.goplus.appKey, time, sign }),
      signal: AbortSignal.timeout(30_000),
    });
    const json: any = await res.json();
    if (json?.code === 1 && json?.result?.access_token) {
      cachedToken = { token: json.result.access_token, expires: json.result.expires_in ? now + json.result.expires_in : now + 3600 };
      return cachedToken.token;
    }
  } catch {
    /* fall through to keyless */
  }
  return null;
}

export type GoPlusTokenSecurity = Record<string, any>;

export async function getTokenSecurity(
  chain: ChainKey,
  address: string
): Promise<{ data: GoPlusTokenSecurity | null; observed_at: string; ok: boolean; error?: string }> {
  const observed_at = new Date().toISOString();
  const chainId = CHAINS[chain].goplusId;
  const addr = address.toLowerCase();
  const token = await getAccessToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = token;
  try {
    const url = `${config.goplus.baseUrl}/api/v1/token_security/${chainId}?contract_addresses=${addr}`;
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
    const json: any = await res.json();
    if (json?.code !== 1) return { data: null, observed_at, ok: false, error: json?.message ?? `code ${json?.code}` };
    const data = json?.result?.[addr] ?? null;
    return { data, observed_at, ok: data != null, error: data ? undefined : "token not indexed by GoPlus" };
  } catch (e: any) {
    return { data: null, observed_at, ok: false, error: e?.message ?? String(e) };
  }
}
