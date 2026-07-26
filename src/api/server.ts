import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tokenVerdict, tokenVerdictDeep, tokenVerdictCourtroom, coarseVerdict, type Tier } from "../engine/verdict.js";
import { verityCheck } from "../engine/check.js";
import { auditContract } from "../engine/contract.js";
import { checkKol } from "../actionguard/kolcheck.js";
import { socialAuthenticity } from "../actionguard/socialauth.js";
import { settleDispute } from "../engine/settle.js";
import { snapshotOf, diffSnapshots, type Snapshot } from "../monitor/watch.js";
import { verdictCardMarkdown, verdictCardTweet } from "../engine/card.js";
import { attestVerdict, getRegistryStats } from "../attest/registry.js";
import { verifyReceipt, signReceipt, signerAddress } from "../attest/sign.js";
import { walletPnl } from "../engine/pnl.js";
import { walletReport } from "../engine/walletreport.js";
import { txReport } from "../engine/txreport.js";
import { dyorReport } from "../engine/dyor.js";
import { researchAnything } from "../engine/research.js";
import { askAletheia } from "../engine/ask.js";
import { solanaVerdict } from "../engine/solana.js";
import { resolveOutcome } from "../engine/resolver.js";
import { evaluateTx } from "../engine/firewall.js";
import { guardWallet } from "../engine/guardian.js";
import { copyIntel } from "../engine/copytrade.js";
import { taxReport } from "../engine/tax.js";
import { airdropSybilCheck } from "../engine/airdrop.js";
import { auditAgent } from "../audit/audit.js";
import { proveFact } from "../evidence/prove.js";
import { socialPulse } from "../pulse/pulse.js";
import { repoRadar } from "../repo/radar.js";
import { scanContent } from "../actionguard/promptfw.js";
import { copySignal } from "../actionguard/copysignal.js";
import { trenchScan } from "../actionguard/trench.js";
import { verifyOutput } from "../actionguard/verifier.js";
import { reviewDoc } from "../actionguard/docreview.js";
import { preTxGuardian } from "../actionguard/pretx.js";
import { checkCounterparty } from "../actionguard/counterparty.js";
import { huntImpersonation } from "../actionguard/impersonation.js";
import { actionGuard } from "../actionguard/actionguard.js";
import { CHAINS, CHAIN_DATA_COVERAGE, chainsWithWalletCoverage, type ChainKey } from "../config.js";
import { OKX_PAY_ENABLED, buildOkxPayMiddleware, initOkxPay, paidRouteInfo, usageReply } from "./okxpay.js";
import { grantsInternalAccess } from "./access.js";
import { rateLimited } from "./ratelimit.js";

const app = new Hono();

// The app sits behind Caddy which terminates TLS, so the x402 SDK (which reads c.req.url) sees
// the internal http:// scheme and stamps the challenge's resource.url as http. OKX's spec wants
// https. This outer wrapper rewrites resource.url http->https on the 402 PAYMENT-REQUIRED header
// when the original request arrived over https (X-Forwarded-Proto) — making the challenge fully
// spec-compliant without touching the SDK.
/**
 * CORS, mounted FIRST so a preflight short-circuits ahead of the paywall.
 *
 * A preflight carries no payment by definition, so a paywall that sees OPTIONS answers 402 — the
 * preflight fails and the real request can never be made from a browser-based or cross-origin agent.
 * And without Access-Control-Expose-Headers a browser cannot READ the PAYMENT-REQUIRED header even on
 * a successful 402, so it cannot construct a payment: the entire x402 flow is invisible to it.
 *
 * Measured against a listed, transacting ASP (ShieldSuite #4959), which answers OPTIONS 204 and
 * exposes PAYMENT-REQUIRED / PAYMENT-RESPONSE. All three of ours returned 402 to a preflight with zero
 * access-control headers.
 */
const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type,Authorization,X-PAYMENT,PAYMENT-SIGNATURE",
  "access-control-expose-headers": "PAYMENT-REQUIRED,PAYMENT-RESPONSE,X-PAYMENT-RESPONSE",
  "access-control-max-age": "86400",
};

app.use("*", async (c, next) => {
  if (c.req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  await next();
  c.res.headers.set("access-control-allow-origin", CORS["access-control-allow-origin"]!);
  c.res.headers.set("access-control-allow-headers", CORS["access-control-allow-headers"]!);
  c.res.headers.set("access-control-expose-headers", CORS["access-control-expose-headers"]!);
});

if (OKX_PAY_ENABLED) {
  // The app sits behind Caddy which terminates TLS, so Hono's c.req.url carries the internal http://
  // scheme and the x402 SDK stamps the challenge's resource.url as http. OKX's spec wants https.
  // We rebuild the request with an https URL (when it arrived over https per X-Forwarded-Proto)
  // BEFORE the payment middleware reads it, so the challenge is spec-correct at the source.
  app.use("*", async (c, next) => {
    try {
      const proto = c.req.header("x-forwarded-proto") || "";
      if (proto.includes("https") && c.req.url.startsWith("http://")) {
        c.req.raw = new Request(c.req.url.replace(/^http:\/\//, "https://"), c.req.raw);
      }
    } catch { /* leave the request untouched on any edge case */ }
    await next();
    // The x402 challenge + body-mirror + decimals are now produced natively by the SDK's documented
    // `unpaidResponseBody` hook (see okxpay.ts) — header by the SDK, body by the hook — so there is no
    // hand-rolled 402 override here to fight Hono's `set res` header-merge. Nothing to patch post-hoc.
  });
  // Official OKX Agent Payments (x402) — must be registered BEFORE routes so it can gate them.
  // Only the registered A2MCP endpoints are charged; everything else passes through free.
  app.use("*", buildOkxPayMiddleware());

  // Runs AFTER payment has settled, BEFORE the route handler. A request that carries no input at all
  // gets the service's contract instead of a 400.
  //
  // Two reasons, and they point the same way. First, payment settles in the middleware above, so a 400
  // from a handler means the caller was charged and handed nothing — the same defect as returning a
  // 4xx for an unsupported chain. Second, OKX's availability probe sends an empty body, and a listed
  // ASP was made to change precisely this behaviour during its review (ShieldSuite commit eff7c6d,
  // "update x402 middleware logic to comply with okx review"; they also had to stop rejecting a paid
  // request whose body was absent). Doing it here covers all 16 paid routes at one point rather than
  // editing 59 separate validation branches, each of which could drift.
  //
  // Scope is deliberately narrow: ONLY a genuinely empty body. A body that is present and wrong still
  // gets its own specific 400, which is the useful diagnostic for a real caller error.
  app.use("*", async (c, next) => {
    if (c.req.method !== "POST" || !paidRouteInfo(new URL(c.req.url).pathname)) return next();
    let raw = "";
    try { raw = await c.req.raw.clone().text(); } catch { /* unreadable body: fall through to the handler */ }
    const trimmed = raw.trim();
    const empty = !trimmed || trimmed === "{}" || trimmed === "null";
    if (!empty) return next();
    return c.json(usageReply(new URL(c.req.url).pathname), 200);
  });
}

// Serve the self-contained dashboard at "/" (read once at module load).
const WEB_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
let DASHBOARD_HTML = "";
try { DASHBOARD_HTML = readFileSync(join(WEB_DIR, "app.html"), "utf8"); } catch { DASHBOARD_HTML = "<h1>Aletheia</h1><p>Dashboard asset missing.</p>"; }
app.get("/", (c) => c.html(DASHBOARD_HTML));

let PROOF_DECK_HTML = "";
try { PROOF_DECK_HTML = readFileSync(join(WEB_DIR, "proof-deck.html"), "utf8"); } catch { PROOF_DECK_HTML = "<h1>Proof deck coming soon.</h1>"; }
app.get("/proof-deck.html", (c) => c.html(PROOF_DECK_HTML));
app.get("/proof-deck", (c) => c.html(PROOF_DECK_HTML));
// Same page at /proof, so all three ASPs expose the judge-facing deck at the identical path.
app.get("/proof", (c) => c.html(PROOF_DECK_HTML));

/** Static proof assets (screenshots for the pitch/Notion). Served from web/proof/. */
app.get("/proof/:file", (c) => {
  const file = c.req.param("file").replace(/[^a-zA-Z0-9._-]/g, "");
  try {
    const buf = readFileSync(join(WEB_DIR, "proof", file));
    const ext = (file.split(".").pop() || "").toLowerCase();
    const ct = ext === "png" ? "image/png" : ext === "jpg" || ext === "jpeg" ? "image/jpeg" : ext === "svg" ? "image/svg+xml" : "application/octet-stream";
    return c.body(buf as any, 200, { "Content-Type": ct, "Cache-Control": "public, max-age=86400" });
  } catch { return c.text("not found", 404); }
});

app.get("/health", (c) => c.json({
  ok: true, service: "aletheia", version: "v0.1.0",
  chains: Object.keys(CHAINS),
  signer_address: signerAddress(),
  // Which chains the wallet services can actually assess, published free so a caller can find out
  // BEFORE paying. Listing a chain is not the same as having data for it: X Layer has no approval
  // index and no asset-transfer history, so a wallet assessment there returns INSUFFICIENT_DATA.
  // This is deliberately not a 4xx at call time — the x402 middleware settles payment before the
  // handler runs, so refusing there would charge and deliver nothing.
  wallet_data_coverage: CHAIN_DATA_COVERAGE,
  wallet_chains_supported: chainsWithWalletCoverage(),
}));

/** The core endpoint. Charged per call via the OKX x402 middleware (see okxpay.ts). */
/** Attach a recoverable EIP-191 signature to any verdict that doesn't already carry one, so EVERY
 *  Aletheia service ships provable — the signer + canonical claim recover offline and any altered field
 *  breaks the signature. No-op when the engine already signed or signing is unavailable. */
async function signed<T>(kind: string, canonical: Record<string, unknown>, result: T): Promise<T> {
  const r = result as any;
  if (r && typeof r === "object" && !r.signed) {
    try { r.signed = await signReceipt({ kind, ...canonical }); } catch { /* signing is best-effort */ }
  }
  return result;
}

app.post("/verdict", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  const address = body.address as string;
  // The PAID verdict defaults to `full`, which runs the live fork buy/sell simulation.
  //
  // It used to default to `flag` — static reads only — so a caller who sent just {chain, address}
  // received `provenance.simulation: "NONE"` in about 2ms, while the listing describes this service as
  // "a live buy/sell fork-simulation ... cross-checked by a multi-model jury". The capability was real
  // and reachable at tier:"full", but nobody calling the obvious way ever saw it, and a description
  // that promises what the default does not deliver is exactly what gets a listing rejected.
  //
  // Measured: `full` returns MULTI_VECTOR across 3 origins in ~10s, far inside the 300s payment window.
  // Speed-sensitive callers can still ask for tier:"flag" explicitly; the free GET preview below stays
  // on `flag` because it is unpaid and must answer instantly.
  const tier = (body.tier ?? "full") as Tier;
  const err = validate(chain, address, tier);
  if (err) return c.json({ error: err }, 400);
  try {
    const verdict: any = await tokenVerdict(chain, address, tier);
    return c.json(await signed("token-verdict", { subject: address, chain, verdict: verdict.verdict, score: verdict.score, observed_at: verdict.generated_at }, verdict));
  } catch (e: any) {
    return c.json({ error: "verdict_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Aletheia Check — the flagship one-call safety gate. Auto-detects token / tx / url / content,
 *  runs the deterministic check + a diverse multi-model jury → SAFE/CAUTION/UNSAFE/INSUFFICIENT_EVIDENCE
 *  with a Proof Pack + plain-English narration. The single call an agent runs before it acts. */
app.post("/check", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const subject = body.subject ?? body.tx ?? body.address ?? body.url ?? body.content;
  const chain = (body.chain ?? "ethereum") as ChainKey;
  if (subject === undefined || subject === null || subject === "")
    return c.json({ error: "provide `subject` — a token address, a {to,...} transaction, a URL, or a content string" }, 400);
  try { return c.json(await verityCheck(subject, chain)); }
  catch (e: any) { return c.json({ error: "check_failed", detail: e?.message ?? String(e) }, 500); }
});

/** Settle It — the evidence court: two sides of any argument → an impartial jury ruling + final word. */
app.post("/settle", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const question = body.question ?? body.dispute ?? body.subject;
  if (!question) return c.json({ error: "provide `question` (the dispute), optionally `side_a` and `side_b`" }, 400);
  try { return c.json(await settleDispute(String(question), body.side_a ?? body.sideA, body.side_b ?? body.sideB)); }
  catch (e: any) { return c.json({ error: "settle_failed", detail: e?.message }, 500); }
});

/** KOL / analyst trust check — is an X account a real credible voice or a bot/paid shill? */
app.post("/kol", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const handle = body.handle ?? body.subject ?? body.username;
  if (!handle) return c.json({ error: "handle (X username) required" }, 400);
  try { const r: any = await checkKol(String(handle)); return c.json(await signed("kol", { handle: r.handle, verdict: r.verdict, trust_score: r.trust_score, observed_at: r.observed_at }, r)); } catch (e: any) { return c.json({ error: "kol_failed", detail: e?.message }, 500); }
});

/** Social-hype authenticity — is the buzz around a token organic or manufactured shilling? */
app.get("/social/:query", async (c) => {
  const q = c.req.param("query") ?? "";
  if (q.trim().length < 2) return c.json({ error: "query too short" }, 400);
  try { return c.json(await socialAuthenticity(q)); } catch (e: any) { return c.json({ error: "social_failed", detail: e?.message }, 500); }
});

/** Free COARSE preview for humans/quick tests — headline only, never the paid evidence/signals.
 *  The full evidence-linked verdict + signed receipt is the paid POST /verdict (x402). */
app.get("/verdict/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  const tier = (c.req.query("tier") ?? "flag") as Tier;
  const err = validate(chain, address, tier);
  if (err) return c.json({ error: err }, 400);
  try {
    const verdict = await tokenVerdict(chain, address, tier);
    return c.json(coarseVerdict(verdict));
  } catch (e: any) {
    return c.json({ error: "verdict_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Deep committee report (A2A / deep tier). */
app.post("/report", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const err = validate(body.chain, body.address, "deep");
  if (err) return c.json({ error: err }, 400);
  try {
    return c.json(await tokenVerdictDeep(body.chain, body.address));
  } catch (e: any) {
    return c.json({ error: "report_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Stateless monitoring check: pass previous_snapshot to get reasoned alerts on material changes. */
app.post("/watch/check", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const err = validate(body.chain, body.address, "full");
  if (err) return c.json({ error: err }, 400);
  try {
    const { snap } = await snapshotOf(body.chain, body.address);
    const compared = !!body.previous_snapshot;
    const alerts = compared ? diffSnapshots(body.previous_snapshot as Snapshot, snap) : [];
    const observed_at = new Date().toISOString();
    // Signed like every other Aletheia service. This one was the sole exception, which undercuts the
    // whole proposition — an unsigned snapshot cannot be proved to have come from us, and it is the
    // snapshot a caller stores and passes back on the next call, so it is exactly the value that has
    // to be tamper-evident.
    //
    // `compared` is stated explicitly because `alerts: []` is ambiguous on its own: with no prior
    // snapshot to diff against, an empty list means "nothing to compare", not "nothing changed", and
    // a buyer cannot tell those apart from the array alone.
    return c.json(await signed("watchdog", {
      chain: body.chain, address: body.address, compared, alert_count: alerts.length, observed_at,
    }, {
      service: "watchdog",
      chain: body.chain,
      address: body.address,
      observed_at,
      compared,
      alerts,
      alert_count: alerts.length,
      headline: compared
        ? (alerts.length ? `${alerts.length} material change(s) since the snapshot you supplied`
                         : "no material change since the snapshot you supplied")
        : "baseline snapshot taken — store it and pass it back as previous_snapshot to detect changes",
      snapshot: snap,
    }));
  } catch (e: any) {
    return c.json({ error: "watch_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Shareable verdict card (markdown + tweet) — Best Product UX + Social Buzz. */
app.get("/card/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  const err = validate(chain, address, "full");
  if (err) return c.json({ error: err }, 400);
  try {
    const v = await tokenVerdict(chain, address, "full");
    return c.json({ markdown: verdictCardMarkdown(v), tweet: verdictCardTweet(v), verdict: coarseVerdict(v) });
  } catch (e: any) {
    return c.json({ error: "card_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Commit a verdict on-chain (X Layer proof-of-correctness ledger). */
app.post("/attest", async (c) => {
  // Runs a full verdict AND writes on-chain (gas) — server/A2A only (internal secret), never free public.
  if (!grantsInternalAccess((n) => c.req.header(n) ?? "")) return c.json({ error: "payment_required", detail: "On-chain attestation is a paid/internal action." }, 402);
  const body = await c.req.json().catch(() => ({}));
  const err = validate(body.chain, body.address, "full");
  if (err) return c.json({ error: err }, 400);
  try {
    const v = await tokenVerdict(body.chain, body.address, "full");
    const att = await attestVerdict(v);
    return c.json({ verdict: v.verdict, score: v.score, attestation: att, note: att ? "committed on X Layer" : "attestation not configured" });
  } catch (e: any) {
    return c.json({ error: "attest_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** The Aletheia Courtroom — Prosecutor vs Defense, Aletheia rules (Creative Genius surface). */
app.get("/courtroom/:chain/:address", async (c) => {
  // Deep paid-equivalent surface — server/A2A only (internal secret). Not a free public route, so it
  // cannot be used to obtain the deep-tier product without payment.
  if (!grantsInternalAccess((n) => c.req.header(n) ?? "")) return c.json({ error: "payment_required", detail: "The deep courtroom ruling is a paid deep-tier service." }, 402);
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  const err = validate(chain, address, "deep");
  if (err) return c.json({ error: err }, 400);
  try {
    return c.json(await tokenVerdictCourtroom(chain, address));
  } catch (e: any) {
    return c.json({ error: "courtroom_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** FREE, rate-limited Creative-Genius demo of the Evidence Court. Shows the prosecutor/defense debate
 *  + jury ruling (the creative asset), with only a COARSE verdict (no paid evidence bundle). Rate-limited
 *  per client because it runs a deep verdict + jury. The full evidence-linked verdict + signed receipt is
 *  the paid API — so this showcase never gives away the paid product, it just demonstrates the creativity. */
app.get("/demo/courtroom/:chain/:address", async (c) => {
  const ip = (c.req.header("x-forwarded-for")?.split(",")[0]?.trim()) || c.req.header("x-real-ip") || "anon";
  if (rateLimited(`demo-courtroom:${ip}`, 3, 10 * 60_000))
    return c.json({ error: "rate_limited", detail: "Free courtroom demo is limited to 3 runs per 10 minutes per client. Use the paid API for unlimited access." }, 429);
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  const err = validate(chain, address, "deep");
  if (err) return c.json({ error: err }, 400);
  try {
    const { verdict, ruling } = await tokenVerdictCourtroom(chain, address);
    return c.json({ demo: true, verdict: coarseVerdict(verdict), ruling, note: "Free Creative-Genius demo — the courtroom debate + jury ruling. The full evidence-linked verdict + signed receipt is the paid API." });
  } catch (e: any) {
    return c.json({ error: "courtroom_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** ActionGuard — the pre-action firewall: compose checks → one signed ALLOW/REVIEW/BLOCK. */
app.post("/actionguard", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  if (!["transaction", "content", "counterparty"].includes(body.type)) return c.json({ error: "type must be transaction|content|counterparty" }, 400);
  try { const r: any = await actionGuard(body); return c.json(await signed("actionguard", { action_type: r.action_type, decision: r.decision, trace_id: r.trace_id, observed_at: r.observed_at }, r)); } catch (e: any) { return c.json({ error: "actionguard_failed", detail: e?.message }, 500); }
});

/** Counterparty check — vet an address before transacting. */
app.get("/counterparty/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: "unsupported chain" }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid address" }, 400);
  try { return c.json(await checkCounterparty(chain, address)); } catch (e: any) { return c.json({ error: "counterparty_failed", detail: e?.message }, 500); }
});

/** Brand-impersonation hunter. */
app.post("/impersonation", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  if (!body.brand) return c.json({ error: "brand is required" }, 400);
  try { return c.json(await huntImpersonation(String(body.brand), body.official_domain)); } catch (e: any) { return c.json({ error: "impersonation_failed", detail: e?.message }, 500); }
});

/** AI Output Verifier — multi-model cross-check of an answer. */
app.post("/verify", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  if (!body.question || !body.answer) return c.json({ error: "question and answer are required" }, 400);
  try { return c.json(await verifyOutput(String(body.question), String(body.answer))); } catch (e: any) { return c.json({ error: "verify_failed", detail: e?.message }, 500); }
});

/** Contract/Invoice Reviewer — doc (text or url) → risk verdict. */
app.post("/docreview", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  if (!body.text && !body.url) return c.json({ error: "text or url is required" }, 400);
  try { return c.json(await reviewDoc({ text: body.text, url: body.url })); } catch (e: any) { return c.json({ error: "docreview_failed", detail: e?.message }, 500); }
});

/** Pre-Transaction Guardian — decode + simulate expected changes + firewall → ALLOW/REVIEW/BLOCK. */
app.post("/pretx", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  if (!(chain in CHAINS)) return c.json({ error: "unsupported chain" }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(body.to ?? "")) return c.json({ error: "invalid target address" }, 400);
  try { return c.json(await preTxGuardian(chain, { to: body.to, data: body.data, value: body.value })); } catch (e: any) { return c.json({ error: "pretx_failed", detail: e?.message }, 500); }
});

/** Prompt Firewall — scan untrusted content for injection before an agent follows it. */
app.post("/firewall/content", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  if (typeof body.content !== "string" || !body.content) return c.json({ error: "content (string) is required" }, 400);
  return c.json(scanContent(body.content));
});

/** Copy-signal — smart-money flow on a token (OKX Onchain OS). */
app.get("/copysignal/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid address" }, 400);
  try { return c.json(await copySignal(chain, address)); } catch (e: any) { return c.json({ error: "copysignal_failed", detail: e?.message }, 500); }
});

/** Trench scanner — launch due diligence (OKX memepump). */
app.get("/trench/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid address" }, 400);
  try { return c.json(await trenchScan(chain, address)); } catch (e: any) { return c.json({ error: "trench_failed", detail: e?.message }, 500); }
});

/** RepoRadar — GitHub due diligence → LEGIT/COSMETIC/RED_FLAG from cheap gh-API signals. */
app.post("/repo", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const input = body.repo ?? body.url ?? body.repository;
  if (!input || typeof input !== "string") return c.json({ error: "repo (owner/name or github URL) is required" }, 400);
  try {
    return c.json(await repoRadar(input));
  } catch (e: any) {
    return c.json({ error: "repo_radar_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Social Pulse — cross-platform sentiment verdict (Twitter + Reddit + YouTube) → HYPE/ORGANIC/DEAD. */
app.get("/pulse/:query", async (c) => {
  const query = c.req.param("query") ?? "";
  if (query.trim().length < 2) return c.json({ error: "query too short" }, 400);
  try {
    return c.json(await socialPulse(query));
  } catch (e: any) {
    return c.json({ error: "pulse_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Verified-evidence — prove a claim against a live URL (hashed snapshot + grounded, no-fabrication extraction). */
app.post("/prove", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  if (!body.url || !/^https?:\/\//i.test(body.url)) return c.json({ error: "url must be a valid http(s) URL" }, 400);
  if (!body.query || typeof body.query !== "string") return c.json({ error: "query is required" }, 400);
  try {
    return c.json(await proveFact(body.url, body.query));
  } catch (e: any) {
    return c.json({ error: "prove_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** AgentAudit — trust-score another AI agent/ASP (injection, accuracy, latency, cost). */
app.post("/audit", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const endpoint = body.endpoint ?? body.baseUrl;
  if (!endpoint || !/^https?:\/\//.test(endpoint)) return c.json({ error: "endpoint must be a valid http(s) URL" }, 400);
  if (!body.model) return c.json({ error: "model is required" }, 400);
  // SECURITY: never fall back to the server's own 0G key based on the caller-supplied endpoint string.
  // A caller could pass a URL merely CONTAINING "router-api.0g.ai" that resolves to their own host and
  // capture the Bearer key. Auditing the 0G model requires the caller to bring its own key.
  const apiKey = body.api_key ?? body.apiKey;
  try {
    const r = await auditAgent(
      { baseUrl: endpoint, model: body.model, apiKey, headers: body.headers, system: body.system },
      { pricing: { inputPerM: body.pricing_input_per_m, outputPerM: body.pricing_output_per_m } }
    );
    return c.json(await signed("agent-audit", { subject: endpoint, model: body.model, grade: (r as any).grade, score: (r as any).score, observed_at: (r as any).generated_at }, r));
  } catch (e: any) {
    return c.json({ error: "audit_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Agent transaction firewall — decode a proposed tx and return ALLOW/WARN/BLOCK before signing. */
app.post("/firewall", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(body.to ?? "")) return c.json({ error: "invalid target address" }, 400);
  try {
    return c.json(await evaluateTx(chain, { to: body.to, from: body.from, data: body.data, value: body.value }));
  } catch (e: any) {
    return c.json({ error: "firewall_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Solana SPL token verdict — authorities + Token-2022 extensions + Jupiter tradeability. */
app.get("/solana/:mint", async (c) => {
  const mint = c.req.param("mint") ?? "";
  const tier = (c.req.query("tier") ?? "full") as "flag" | "full";
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(mint)) return c.json({ error: "invalid SPL mint address" }, 400);
  try {
    const v = await solanaVerdict(mint, tier === "flag" ? "flag" : "full");
    return c.json(coarseVerdict(v as any));
  } catch (e: any) {
    return c.json({ error: "solana_verdict_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Airdrop sybil check — score a wallet's farming footprint (hub-funded + thin activity). */
app.get("/sybil/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  try {
    return c.json(await airdropSybilCheck(chain, address));
  } catch (e: any) {
    return c.json({ error: "sybil_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Crypto tax — realized gain/loss report (FIFO) from the reconstructed trade ledger. */
app.get("/tax/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  const yr = c.req.query("year");
  try {
    return c.json(await taxReport(chain, address, { year: yr ? Number(yr) : undefined }));
  } catch (e: any) {
    return c.json({ error: "tax_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Copy-intelligence — grade a wallet's copyworthiness + surface its open positions. */
app.get("/copy/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  try {
    return c.json(await copyIntel(chain, address));
  } catch (e: any) {
    return c.json({ error: "copy_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Wallet guardian — scan live token approvals, return a prioritized revoke list. */
app.get("/guardian/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  try {
    return c.json(await guardWallet(chain, address));
  } catch (e: any) {
    return c.json({ error: "guardian_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Wallet trading scorecard — fee-adjusted realized PnL + win-rate (copy-intelligence surface). */
app.get("/wallet/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  try {
    return c.json(await walletPnl(chain, address));
  } catch (e: any) {
    return c.json({ error: "wallet_pnl_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Wallet Health — one call folds the three wallet-safety checks into a single graded report:
 *  risky live approvals to revoke + sybil-farming footprint + fee-adjusted trading track record. */
/** Ask Aletheia — one plain-language question, answered with the full toolset + a jury self-check, signed. */
app.post("/ask", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const question = body.question ?? body.q ?? body.query ?? body.subject;
  const chain = (body.chain ?? "ethereum") as ChainKey;
  if (!question || String(question).trim().length < 3) return c.json({ error: "ask a question" }, 400);
  try { return c.json(await askAletheia(String(question), chain)); }
  catch (e: any) { return c.json({ error: "ask_failed", detail: e?.message ?? String(e) }, 500); }
});

/** Research on ANYTHING — auto-detects token / wallet / solana / repo / URL / topic and runs the right deep investigation. */
app.post("/research", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const subject = body.subject ?? body.topic ?? body.query ?? body.address ?? body.url;
  const chain = (body.chain ?? "ethereum") as ChainKey;
  if (!subject) return c.json({ error: "provide a subject: a token/wallet address, a URL, or a topic/claim" }, 400);
  try { return c.json(await researchAnything(subject, chain)); }
  catch (e: any) { return c.json({ error: "research_failed", detail: e?.message ?? String(e) }, 500); }
});

/** DYOR Research Agent — signed, grounded deep-research report on a token (the DYOR checklist, automated). */
app.post("/dyor", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  const address = String(body.address ?? "");
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  try { return c.json(await dyorReport(chain, address)); }
  catch (e: any) { return c.json({ error: "dyor_failed", detail: e?.message ?? String(e) }, 500); }
});

/** Wallet Deep Report — signed "who is this wallet": classification + approvals/sybil/PnL/trader-grade. */
app.post("/wallet-report", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  const address = String(body.address ?? "");
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  // As in /wallet-health: no 4xx for an uncovered chain, because payment has already settled by the
  // time this runs. walletReport reports INSUFFICIENT_DATA with its coverage instead.
  try { return c.json(await walletReport(chain, address)); }
  catch (e: any) { return c.json({ error: "wallet_report_failed", detail: e?.message ?? String(e) }, 500); }
});

/** Transaction Deep Report — signed "what will this tx do to me before I sign": effects + risks. */
app.post("/tx-report", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(body.to ?? "")) return c.json({ error: "invalid target address (to)" }, 400);
  try { return c.json(await txReport(chain, { to: body.to, from: body.from, data: body.data, value: body.value })); }
  catch (e: any) { return c.json({ error: "tx_report_failed", detail: e?.message ?? String(e) }, 500); }
});

app.post("/wallet-health", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  const address = String(body.address ?? "");
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  // Deliberately NOT a 400 for a chain with no data coverage. The x402 middleware is registered with
  // `app.use("*", ...)` before every route, so the payment has already settled by the time this
  // handler runs — verified with a real paid call, which returned a PAYMENT-RESPONSE header. A 4xx
  // here would mean charged and handed nothing at all, which is strictly worse than the honest
  // INSUFFICIENT_DATA below: that at least tells the payer which sources were unreachable, names the
  // chains that work, and is signed. The place to warn someone off is the listing, before they pay.
  try {
    const [approvals, sybil, pnl] = await Promise.allSettled([
      guardWallet(chain, address),
      airdropSybilCheck(chain, address),
      walletPnl(chain, address),
    ]);
    const val = (r: PromiseSettledResult<any>) => (r.status === "fulfilled" ? r.value : { error: (r.reason as Error)?.message ?? String(r.reason) });
    const g: any = val(approvals), s: any = val(sybil), p: any = val(pnl);
    const revoke = (g?.maliciousSpenderCount ?? 0) + (g?.unlimitedCount ?? 0);
    const sybilFlag = s?.label === "LIKELY_SYBIL";

    // A sub-check that could not run tells us NOTHING about the wallet — and every risk condition
    // below reads a field off the result, so an errored check leaves them all `undefined` and every
    // condition false. That produced a signed "HEALTHY — clean footprint" verdict for a wallet where
    // all three data sources had failed (X Layer is not covered by the approvals API, and transfer
    // history is unavailable there). A risk report backed by no data must never read as an all-clear:
    // the signature only lends it more authority. Absence of evidence is not evidence of safety.
    const ran = (r: any) => !!r && r.ok !== false && !r.error;
    const checks = { approvals: ran(g), sybil: ran(s), trading: ran(p) };
    const unavailable = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
    const why = [
      !checks.approvals && g?.error ? `approvals: ${g.error}` : null,
      !checks.sybil && s?.error ? `sybil: ${s.error}` : null,
      !checks.trading && p?.error ? `trading: ${p.error}` : null,
    ].filter(Boolean) as string[];

    const flagged = (checks.approvals && ((g?.maliciousSpenderCount ?? 0) > 0 || (g?.worstRisk ?? 0) >= 3))
      || (checks.sybil && sybilFlag);
    // Only the checks that actually ran can support a conclusion.
    const risk = flagged
      ? "AT_RISK"
      : !checks.approvals && !checks.sybil
        ? "INSUFFICIENT_DATA"   // nothing that bears on risk was reachable
        : "HEALTHY";

    const parts: string[] = [];
    if (checks.approvals && revoke > 0) parts.push(`${revoke} approval(s) worth revoking (${g?.maliciousSpenderCount ?? 0} to flagged spenders)`);
    if (checks.sybil && sybilFlag) parts.push("sybil-farming footprint detected");

    const headline = risk === "AT_RISK"
      ? parts.join("; ")
      : risk === "INSUFFICIENT_DATA"
        ? `cannot assess this wallet: ${why.join("; ") || `${unavailable.join(", ")} unavailable`}`
        : unavailable.length
          // Partial coverage is stated plainly rather than rounded up to "clean".
          ? `no risk found in the checks that ran; ${unavailable.join(", ")} unavailable, so this is not a full all-clear`
          : "no urgent approval risk; clean footprint";

    const out = {
      service: "wallet_health",
      chain, address,
      status: risk,
      observed_at: new Date().toISOString(),
      headline,
      // Coverage travels with the verdict so a caller can see exactly what it rests on.
      checks_run: checks,
      checks_unavailable: unavailable,
      unavailable_reasons: why,
      assessed_on: Object.entries(checks).filter(([, ok]) => ok).map(([k]) => k),
      approvals: g,
      sybil: s,
      trading: p,
    };
    return c.json(await signed("wallet-health", { address, chain, status: risk, checks_run: checks, observed_at: out.observed_at }, out));
  } catch (e: any) {
    return c.json({ error: "wallet_health_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Contract Audit — Slither static analysis on any verified contract → GO/CAUTION/AVOID + findings. */
app.post("/contract-audit", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const chain = body.chain as ChainKey;
  const address = String(body.address ?? "");
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  try {
    const r: any = await auditContract(chain, address);
    return c.json(await signed("contract-audit", { address, chain, verdict: r.verdict, score: r.score, observed_at: r.observed_at }, r));
  } catch (e: any) {
    return c.json({ error: "contract_audit_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Resolve a token's real outcome ("did it rug?") — closes the accuracy loop. */
app.get("/resolve/:chain/:address", async (c) => {
  const chain = c.req.param("chain") as ChainKey;
  const address = c.req.param("address") ?? "";
  if (!(chain in CHAINS)) return c.json({ error: `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}` }, 400);
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return c.json({ error: "invalid EVM address" }, 400);
  const baseline = c.req.query("baseline_liquidity_usd");
  try {
    return c.json(await resolveOutcome(chain, address, { baselineLiquidityUsd: baseline != null ? Number(baseline) : null }));
  } catch (e: any) {
    return c.json({ error: "resolve_failed", detail: e?.message ?? String(e) }, 500);
  }
});

/** Public on-chain accuracy record. */
app.get("/registry/stats", async (c) => c.json((await getRegistryStats()) ?? { error: "registry not configured" }));

/** Verify a signed verdict receipt — pass a verdict's `signed` object, get whether it's authentic + unaltered. */
app.post("/receipt/verify", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const s = body.signed ?? body;
  if (!s.signer || !s.message || !s.signature) return c.json({ error: "provide the verdict's `signed` object (signer, message, signature)" }, 400);
  const v = await verifyReceipt({ signer: s.signer, message: s.message, signature: s.signature, expectedSigner: body.expected_signer });
  // The note must never claim Aletheia issued a receipt whose signer was not checked against
  // Aletheia's own address. A cryptographically valid signature from an unknown key is the one case
  // where every step passes and the conclusion is still wrong.
  const note = {
    VALID: "Signature matches AND the signer is Aletheia's published address — authentic and unaltered.",
    VALID_SIGNATURE_UNKNOWN_ISSUER: "Signature is cryptographically valid but the signer is NOT Aletheia. This receipt was issued by someone else.",
    VALID_UNATTRIBUTED: "Signature matches the claimed signer, but this node has no signing key configured, so the issuer could not be confirmed as Aletheia.",
    INVALID_SIGNATURE: "Signature does NOT match — the message was altered or the signature is forged.",
  }[v.verdict];
  return c.json({ ...v, signer: s.signer, note });
});

/** Aletheia's signing identity. The anchor a caller compares a receipt's signer against — offline
 *  verification is only meaningful once you know which address is supposed to have signed. */
app.get("/.well-known/aletheia-signer", (c) => {
  const addr = signerAddress();
  return c.json({
    service: "aletheia",
    scheme: "EIP-191/personal_sign over canonical JSON (stable, recursively sorted keys)",
    signer_address: addr,
    configured: addr !== null,
    usage: "Require a receipt's `signer` to equal this address, then verifyMessage({ address: signer, message, signature }). A receipt signed by any other key was not issued by Aletheia.",
  });
});

function validate(chain: string, address: string, tier: string): string | null {
  if (!chain || !(chain in CHAINS)) return `unsupported chain; use one of: ${Object.keys(CHAINS).join(", ")}`;
  if (!address || !/^0x[a-fA-F0-9]{40}$/.test(address)) return "invalid EVM address";
  if (!["flag", "full", "deep"].includes(tier)) return "tier must be flag|full|deep";
  return null;
}

export function startApi(port = Number(process.env.PORT ?? 8788)) {
  // Fail-closed: never start serving paid routes for free in production. Require the full x402 config
  // (X402_ENABLED=1 + OKX_API_KEY/OKX_SECRET_KEY/OKX_PASSPHRASE + X402_PAY_TO/OKX_PAY_TO). The explicit
  // ALETHEIA_DEV_OPEN=1 escape hatch is for local dev only and must never be set in production.
  if (!OKX_PAY_ENABLED && process.env.ALETHEIA_DEV_OPEN !== "1") {
    console.error("[aletheia] REFUSING TO START — x402 payment is not fully configured and ALETHEIA_DEV_OPEN is not set. Set X402_ENABLED=1 + OKX_API_KEY/OKX_SECRET_KEY/OKX_PASSPHRASE + X402_PAY_TO for production, or ALETHEIA_DEV_OPEN=1 for local dev.");
    process.exit(1);
  }
  serve({ fetch: app.fetch, port });
  console.log(`Aletheia API listening on http://127.0.0.1:${port}`);
  if (OKX_PAY_ENABLED) void initOkxPay(); // sync facilitator/scheme state after start
  return app;
}

export { app };

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").pop()!);
if (isMain) startApi();
