import crypto from "node:crypto";
import { config, CHAINS, type ChainKey } from "../config.js";

/**
 * OKX Onchain OS Market API adapter (v6 DEX Market) — holder clusters + rugPullPercent, bundle/aped
 * (sniper) detection, smart-money signals + leaderboard, wallet PnL. Native to X Layer, free on trial.
 *
 * Auth: standard OKX HMAC. Requires registered creds (OKX_API_KEY/SECRET_KEY/PASSPHRASE[/PROJECT]).
 * Degrades gracefully: if not configured, isConfigured()=false and callers skip the OKX-sourced dimensions.
 */

const BASE = config.okx.base;

export function isConfigured(): boolean {
  return !!(config.okx.apiKey && config.okx.secretKey && config.okx.passphrase);
}

const chainIndex: Record<ChainKey, string> = {
  ethereum: "1", bsc: "56", base: "8453", arbitrum: "42161", polygon: "137", xlayer: "196",
};

function sign(timestamp: string, method: string, requestPath: string, body = ""): string {
  const prehash = timestamp + method + requestPath + body;
  return crypto.createHmac("sha256", config.okx.secretKey!).update(prehash).digest("base64");
}

async function get<T = any>(path: string, params: Record<string, string> = {}): Promise<{ ok: boolean; data: T | null; observed_at: string; error?: string }> {
  const observed_at = new Date().toISOString();
  if (!isConfigured()) return { ok: false, data: null, observed_at, error: "OKX API creds not configured" };
  const qs = new URLSearchParams(params).toString();
  const requestPath = qs ? `${path}?${qs}` : path;
  const timestamp = new Date().toISOString();
  const headers: Record<string, string> = {
    "OK-ACCESS-KEY": config.okx.apiKey!,
    "OK-ACCESS-SIGN": sign(timestamp, "GET", requestPath, ""),
    "OK-ACCESS-TIMESTAMP": timestamp,
    "OK-ACCESS-PASSPHRASE": config.okx.passphrase!,
    "Content-Type": "application/json",
  };
  if (config.okx.project) headers["OK-ACCESS-PROJECT"] = config.okx.project;
  try {
    const res = await fetch(`${BASE}${requestPath}`, { headers, signal: AbortSignal.timeout(30_000) });
    const json: any = await res.json();
    if (json?.code !== "0" && json?.code !== 0) return { ok: false, data: null, observed_at, error: json?.msg ?? `code ${json?.code}` };
    return { ok: true, data: json.data as T, observed_at };
  } catch (e: any) {
    return { ok: false, data: null, observed_at, error: e?.message ?? String(e) };
  }
}

/** Signed POST (some Market endpoints, e.g. signal/list, only accept POST with a JSON body). */
async function post<T = any>(path: string, body: Record<string, unknown>): Promise<{ ok: boolean; data: T | null; observed_at: string; error?: string }> {
  const observed_at = new Date().toISOString();
  if (!isConfigured()) return { ok: false, data: null, observed_at, error: "OKX API creds not configured" };
  const bodyStr = JSON.stringify(body);
  const timestamp = new Date().toISOString();
  const headers: Record<string, string> = {
    "OK-ACCESS-KEY": config.okx.apiKey!,
    "OK-ACCESS-SIGN": sign(timestamp, "POST", path, bodyStr),
    "OK-ACCESS-TIMESTAMP": timestamp,
    "OK-ACCESS-PASSPHRASE": config.okx.passphrase!,
    "Content-Type": "application/json",
  };
  if (config.okx.project) headers["OK-ACCESS-PROJECT"] = config.okx.project;
  try {
    const res = await fetch(`${BASE}${path}`, { method: "POST", headers, body: bodyStr, signal: AbortSignal.timeout(30_000) });
    const json: any = await res.json();
    if (json?.code !== "0" && json?.code !== 0) return { ok: false, data: null, observed_at, error: json?.msg ?? `code ${json?.code}` };
    return { ok: true, data: json.data as T, observed_at };
  } catch (e: any) {
    return { ok: false, data: null, observed_at, error: e?.message ?? String(e) };
  }
}

const MKT = "/api/v6/dex/market";

/** Holder clustering + rugPullPercent (Bubblemaps-class). */
export const getClusterOverview = (chain: ChainKey, token: string) =>
  get(`${MKT}/token/cluster/overview`, { chainIndex: chainIndex[chain], tokenContractAddress: token });

/** Bundle/dev info for launch tokens (Trench-class bundle detection). */
export const getMemepumpToken = (chain: ChainKey, token: string) =>
  get(`${MKT}/memepump/token`, { chainIndex: chainIndex[chain], tokenContractAddress: token });

/** Aped/sniper wallets on a launch. */
export const getApedWallets = (chain: ChainKey, token: string) =>
  get(`${MKT}/memepump/aped`, { chainIndex: chainIndex[chain], tokenContractAddress: token });

/** Same-deployer / cross-chain reuse (scam-token reuse). */
export const getSimilarTokens = (chain: ChainKey, token: string) =>
  get(`${MKT}/memepump/similar`, { chainIndex: chainIndex[chain], tokenContractAddress: token });

/** Smart-money signals for a token (POST-only endpoint). */
export const getSignals = (chain: ChainKey, token: string) =>
  post(`${MKT}/signal/list`, { chainIndex: chainIndex[chain], tokenContractAddress: token });

/** Top profitable traders holding a token. */
export const getTopTraders = (chain: ChainKey, token: string) =>
  get(`${MKT}/token/top-trader`, { chainIndex: chainIndex[chain], tokenContractAddress: token });

/** Wallet PnL (autopsy / copy-worthiness). */
export const getWalletPnL = (chain: ChainKey, wallet: string) =>
  get(`${MKT}/portfolio/recent-pnl`, { chainIndex: chainIndex[chain], walletAddress: wallet });

/** OKX advanced token info (includes their honeypot tag + trade metrics). */
export const getAdvancedInfo = (chain: ChainKey, token: string) =>
  get(`${MKT}/token/advanced-info`, { chainIndex: chainIndex[chain], tokenContractAddress: token });
