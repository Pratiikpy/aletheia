import { OKXFacilitatorClient } from "@okxweb3/app-x402-core";
import { x402ResourceServer, x402HTTPResourceServer, paymentMiddlewareFromHTTPServer } from "@okxweb3/app-x402-hono";
import { ExactEvmScheme } from "@okxweb3/app-x402-evm/exact/server";
import type { MiddlewareHandler } from "hono";
import { grantsInternalAccess } from "./access.js";

/**
 * Official OKX Agent Payments (x402) seller integration - the standard the OKX.AI marketplace
 * validates against. Unpaid calls to the registered A2MCP endpoints get a spec-correct 402 that
 * OKX's Facilitator can verify + settle on X Layer (eip155:196); a paid replay is served.
 *
 * Payment is FAIL-CLOSED. The ONLY unpaid bypass is a server-only internal secret (for Aletheia's own
 * A2A daemon fulfilling a task the client ALREADY paid for via escrow). Browser-forgeable headers
 * (Sec-Fetch-Site, Origin, Referer, Host) are NOT trusted for free access - any HTTP client can set
 * them, which would hand the marketplace validator or any agent the paid result for free and fail x402
 * review. The public web demo uses a SEPARATE, explicitly-free coarse endpoint, never the paid route.
 *
 * Enabled only when X402_ENABLED=1 and all creds are present; otherwise the middleware is a no-op.
 */

const NETWORK = "eip155:196" as const; // X Layer
const PAY_TO = process.env.X402_PAY_TO || process.env.OKX_PAY_TO || "";
const OKX_API_KEY = process.env.OKX_API_KEY || "";
const OKX_SECRET_KEY = process.env.OKX_SECRET_KEY || "";
const OKX_PASSPHRASE = process.env.OKX_PASSPHRASE || "";

export const OKX_PAY_ENABLED = !!(
  process.env.X402_ENABLED === "1" && PAY_TO && OKX_API_KEY && OKX_SECRET_KEY && OKX_PASSPHRASE
);

/** The registered A2MCP marketplace services - prices match the marketplace listing.
 *  Keys carry NO HTTP-method prefix on purpose: the OKX SDK treats a spaceless route key as verb "*"
 *  (matches ANY method), so the paywall returns the standard 402 challenge even for OKX's method-agnostic
 *  availability probe (a bare GET with no body). With a "POST " prefix, that probe misses the route and
 *  falls through to 404/405 — which fails x402 listing validation. */
const ROUTES = {
  "/check": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.03", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Aletheia Check - the one pre-action safety gate. Use when you have ANY subject (an EVM token address, a raw transaction object, a URL, or a content string) and want a single SAFE / CAUTION / UNSAFE / INSUFFICIENT_EVIDENCE decision before acting; it auto-detects the type and runs the right check. For a token-only breakdown use /verdict; for an unsigned-tx decision use /tx-report. Input: {subject, chain?}. Returns: decision, confidence, proof-pack (evidence + jury votes), signed receipt.",
    mimeType: "application/json",
  },
  "/verdict": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.02", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Token Verdict - evidence-linked GO / CAUTION / AVOID for one EVM token before trading (security, market structure, tokenomics, smart-money), with an optional multi-vector buy/sell fork simulation. Use when you have a token contract address and want the token risk breakdown. For a yes/no gate on mixed inputs use /check; for a full bull-vs-bear committee report use /report. Input: {chain, address, tier?: 'flag' (fast, static-only) | 'full' (+fork sim) | 'deep' (+committee)}. Returns: verdict, score, confidence, dimensions, signals+evidence, signed receipt.",
    mimeType: "application/json",
  },
  "/actionguard": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.01", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "ActionGuard - a pre-action firewall that composes transaction-decode + counterparty + prompt-injection + data-loss checks into one ALLOW / REVIEW / BLOCK. Use right before an agent signs a tx, trusts inbound content, or engages a counterparty. For a full pre-sign tx breakdown use /tx-report; for token risk use /verdict. Input: {type: 'transaction'|'content'|'counterparty', plus the matching fields (to/data/value, content/url, or chain/address)}. Returns: decision, per-check evidence, signed trace id.",
    mimeType: "application/json",
  },
  "/audit": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.05", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "AgentAudit - trust-score another AI agent/ASP by probing its endpoint for prompt-injection resistance, accuracy, latency and cost. Use before hiring or relying on another agent. Input: {endpoint (https), model, api_key?}. Returns: grade (A-F/U), dimension scores, failed probes, signed report.",
    mimeType: "application/json",
  },
  "/settle": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.03", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Settle It - an evidence court for a dispute or contested claim: it gathers real web sources, has two AI sides debate, and a diverse jury rules. Use when two parties/agents disagree and you need an evidence-grounded ruling, not one model's opinion. To verify a single AI answer use /verify. Input: {question, side_a?, side_b?}. Returns: ruling, confidence, cited sources, jury votes, full transcript.",
    mimeType: "application/json",
  },
  "/kol": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.02", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "KOL Check - is an X/Twitter account a credible voice or a bot/paid shill? Use before trusting an influencer or caller. Input: {handle}. Returns: 0-100 trust score, verdict, and the signals behind it.",
    mimeType: "application/json",
  },
  "/watch/check": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.01", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Watchdog - an on-demand change monitor for a token or position. Pass the prior snapshot you stored and get reasoned alerts on any material change since then (liquidity pulled, tax raised, ownership/mint flags flipped). Use to re-check something you already verified. Input: {chain, address, previous_snapshot?}. Returns: fresh snapshot + reasoned alerts.",
    mimeType: "application/json",
  },
  "/wallet-health": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.03", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    // Names the chains that actually have the underlying data. X Layer has no approval index and no
    // transfer history, so an assessment there rests on nothing — saying so before purchase is the
    // difference between a useful service and one that takes money for a question it cannot answer.
    description: "Wallet Health - one scan of a wallet: risky approvals to revoke, sybil-farming footprint, and fee-adjusted trading record. Use to assess your own or a counterparty wallet's safety. Chains: ethereum, bsc, base, arbitrum, polygon. Input: {chain, address}. Returns: status + approvals + sybil + trading summary.",
    mimeType: "application/json",
  },
  "/verify": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.02", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Proof-of-Work - verify an AI output/deliverable is correct and grounded via a multi-model jury cross-check. Use to check an answer before you trust or pay for it. For a two-sided dispute use /settle. Input: {question, answer}. Returns: VERIFIED / DISPUTED / LIKELY_WRONG, agreement score, flagged claims.",
    mimeType: "application/json",
  },
  "/contract-audit": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.08", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Contract Audit - Slither static analysis on a verified contract (reentrancy, backdoors, hidden hooks). Use for a code-level audit of a specific contract. For token trade-safety use /verdict. Input: {chain, address}. Returns: GO / CAUTION / AVOID, findings by severity, summary.",
    mimeType: "application/json",
  },
  "/dyor": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.10", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "DYOR Research Agent - deepest automated due-diligence on a token: on-chain data + live buy/sell simulation + social-authenticity + a multi-AI bull-vs-bear committee, every claim source-cited and signed. Use for the fullest token research. A fast token gate is /verdict; open-ended research is /research. Input: {chain, address}. Returns: signed committee report with citations.",
    mimeType: "application/json",
  },
  "/report": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.05", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Token Deep Report - complete structured on-chain fact-set (market, security-sim, smart-money, deployer forensics, insider-flow, sybil clusters) + a bull-vs-bear AI committee -> BUY / HOLD / AVOID, signed and offline-verifiable. Use when you want the full token report, not a quick gate (quick gate = /verdict). Input: {chain, address}. Returns: signed structured report.",
    mimeType: "application/json",
  },
  "/wallet-report": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.03", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Wallet Deep Report - a signed 'who is this wallet': classification (smart-money / airdrop-farmer / risky / normal) + approvals revoke-risk + sybil footprint + fee-adjusted PnL. Chains: ethereum, bsc, base, arbitrum, polygon. Input: {chain, address}. Returns: signed classification + details.",
    mimeType: "application/json",
  },
  "/tx-report": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.02", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Transaction Deep Report - 'what will this transaction do to me before I sign': decoded effects + counterparty / unlimited-approval / token risk -> ALLOW / REVIEW / BLOCK, signed. Use with an unsigned transaction. For a broader multi-check firewall use /actionguard. Input: {chain, to, data?, value?}. Returns: decision + decoded effects, signed.",
    mimeType: "application/json",
  },
  "/research": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.10", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Deep Research on anything - a token, wallet, link, or plain-English topic/claim. Auto-detects the subject, decomposes it into sub-questions, reads and credibility-ranks many sources over multiple rounds, and returns findings where every claim is cited to its source, with a signed receipt. Use for open-ended research; for token-specific due-diligence use /dyor. Input: {subject | question}. Returns: cited findings, sources, signed receipt.",
    mimeType: "application/json",
  },
  "/ask": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.05", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Ask Aletheia - one plain-language question answered with the full toolset: it runs any address through the on-chain safety check, reads any link, grounds the answer in a live web search, then runs a multi-model jury to confirm it isn't hallucinated - and signs it. Use for a single grounded, verified answer. For a multi-round report use /research. Input: {question}. Returns: grounded, jury-checked answer + sources, signed.",
    mimeType: "application/json",
  },
};

let resourceServer: { initialize(): Promise<void> } | null = null;

/** Mirror the x402 challenge into the 402 response BODY using the SDK's documented `unpaidResponseBody`
 *  hook (the same mechanism the live competitor Argus uses). The SDK still emits the PAYMENT-REQUIRED
 *  header itself, so both header-reading and body-reading clients — and OKX's `x402-check` — see a
 *  spec-complete challenge. This replaces a hand-rolled Hono override that fought Hono's `set res`
 *  header-merge and could silently revert the header. We also inject `decimals: 6` on each accepts
 *  entry (USD₮0 isn't in OKX's built-in token list; without it price-resolution fails). */
function mirrorChallenge(accepts: { scheme: string; network: typeof NETWORK; payTo: string; price: string; maxTimeoutSeconds: number }, description: string, mimeType: string) {
  return async (context: any) => {
    const rs: any = resourceServer;
    const requirements = await rs.buildPaymentRequirementsFromOptions([accepts], context);
    const url = context?.adapter?.getUrl?.() ?? "";
    const paymentRequired = await rs.createPaymentRequiredResponse(requirements, { url, description, mimeType }, "Payment required");
    return { contentType: "application/json", body: paymentRequired };
  };
}

/** Route metadata for the empty-body usage reply — path -> {fee, description}. */
export function paidRouteInfo(path: string): { fee: string; description: string } | null {
  const r = (ROUTES as Record<string, any>)[path];
  if (!r) return null;
  return { fee: String(r.accepts?.price ?? "").replace("$", ""), description: String(r.description ?? "") };
}

/**
 * Reply to a PAID request that arrived with no input at all.
 *
 * Payment settles in the middleware before any route handler runs, so answering an empty request with
 * 400 charges the caller and hands them nothing. OKX's availability probe also sends an empty body —
 * a listed ASP (ShieldSuite, commit eff7c6d "comply with okx review") was made to change exactly this
 * during its review. Shaped so it cannot be mistaken for a result: ok is false and there is no verdict.
 */
export function usageReply(path: string) {
  const info = paidRouteInfo(path);
  const desc = info?.description ?? "";
  // The registered descriptions carry their contract as "Input: {...}. Returns: ..." — surface that
  // rather than maintaining a second, drifting copy of it here.
  const inputPart = /Input:\s*(\{[^}]*\}|[^.]*)/i.exec(desc)?.[1]?.trim() ?? "";
  const returnsPart = /Returns:\s*([^.]*)/i.exec(desc)?.[1]?.trim() ?? "";
  return {
    ok: false,
    status: "no_input_supplied",
    endpoint: path,
    fee_usdt: info?.fee ?? null,
    message: "No input was supplied, so nothing was assessed. Send the input shown below in the "
      + "request body. Nothing was computed for this call.",
    what_it_does: (desc.split(" - ").slice(1).join(" - ").split(" Use ")[0] ?? "").trim() || desc,
    expected_input: inputPart || "see the service description",
    returns: returnsPart || null,
  };
}

/** Build the Hono payment middleware. Call once, mount before routes with app.use("*", ...). */
export function buildOkxPayMiddleware(): MiddlewareHandler {
  const facilitatorClient = new OKXFacilitatorClient({
    apiKey: OKX_API_KEY,
    secretKey: OKX_SECRET_KEY,
    passphrase: OKX_PASSPHRASE,
    baseUrl: process.env.OKX_BASE_URL || "https://web3.okx.com",
    syncSettle: false, // async settle - right for high-frequency, sub-$1 agent calls
  });
  const rs = new x402ResourceServer(facilitatorClient).register(NETWORK, new ExactEvmScheme());
  resourceServer = rs;
  // Attach the documented body-mirror hook to every registered route so each 402 carries the challenge
  // in BOTH the header (SDK-native) and the body (this hook) — the robust, SDK-supported form.
  const ROUTES_WITH_MIRROR = Object.fromEntries(
    Object.entries(ROUTES).map(([k, v]) => [k, { ...v, unpaidResponseBody: mirrorChallenge(v.accepts, v.description, v.mimeType) }])
  );
  const httpServer = new x402HTTPResourceServer(rs, ROUTES_WITH_MIRROR as any);
  const PAYMENT_HEADERS = ["payment-signature", "x-payment", "payment"];

  /**
   * Turn a THROW during payment verification into a clean 402 re-challenge.
   *
   * A structurally valid but forged PAYMENT-SIGNATURE (correct base64 JSON, bogus signature) makes the
   * facilitator's verify step throw, and an uncaught throw reaches Hono as a bare
   * `500 Internal Server Error`. Measured on all three of our ASPs before this guard. It fails CLOSED —
   * no free work is ever served — but 500 is the wrong answer to "your payment did not verify", and a
   * reviewer probing the paywall sees a broken service rather than a working one.
   *
   * The correct x402 answer is another 402 carrying the challenge. Rather than hand-roll that challenge
   * and risk drifting from the SDK's shape, re-enter the SDK middleware with the payment headers
   * stripped: to the SDK the call is simply unpaid, so it emits its own canonical 402 — PAYMENT-REQUIRED
   * header and mirrored body both.
   *
   * A throw from the PAID handler downstream must not be converted: the caller has paid, and answering
   * 402 would tell them to pay twice. `entered` records whether control reached `next()`.
   */
  const guard = (inner: MiddlewareHandler): MiddlewareHandler => async (c, next) => {
    // Buffer the body up front: re-entering the middleware needs a second readable copy, and a
    // Request body can only be consumed once.
    const method = c.req.method;
    const body = method === "GET" || method === "HEAD" ? undefined : await c.req.raw.clone().arrayBuffer();
    let entered = false;
    try {
      return await inner(c, async () => { entered = true; await next(); });
    } catch (e) {
      if (entered) throw e; // the paid handler's failure — not a payment problem
      const detail = (e as Error)?.message ?? String(e);
      console.warn(`[okxpay] payment verification threw on ${new URL(c.req.url).pathname}: ${detail}`);
      try {
        const headers = new Headers(c.req.raw.headers);
        for (const h of PAYMENT_HEADERS) headers.delete(h);
        c.req.raw = new Request(c.req.url, { method, headers, body });
        return await inner(c, async () => {
          // Unreachable: with no payment header the SDK must answer 402 rather than grant access.
          throw new Error("payment middleware granted access to an unpaid re-challenge");
        });
      } catch {
        // Last resort: still 402, still JSON, never a bare 500.
        return c.json({ error: "invalid_payment",
                        detail: "PAYMENT-SIGNATURE did not verify. Retry with no payment header to get a fresh challenge." },
                      402);
      }
    }
  };

  httpServer.onProtectedRequest(async (ctx) => {
    const h = (name: string) => ctx.adapter.getHeader(name) || "";
    // Fail-closed: the ONLY unpaid bypass is the server-only internal secret (see access.ts). Browser-
    // forgeable headers are NOT trusted, so agents / the marketplace validator cannot take the paid
    // result for free. The public web demo uses a separate, explicitly-free coarse endpoint.
    if (grantsInternalAccess(h)) return { grantAccess: true };
    return; // everyone else — agents, marketplace, validator, and the browser demo — pays (standard 402)
  });
  return guard(paymentMiddlewareFromHTTPServer(httpServer));
}

/** Sync scheme/facilitator state - MUST run after the server starts, before requests are served. */
export async function initOkxPay(): Promise<void> {
  if (!resourceServer) return;
  try {
    await resourceServer.initialize();
    console.log("[okxpay] facilitator initialized - x402 live on /verdict /actionguard /audit");
  } catch (e) {
    console.error("[okxpay] initialize failed:", (e as Error)?.message ?? e);
  }
}
