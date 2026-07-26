import type { ChainKey } from "../config.js";
import { gather } from "./context.js";
import { buildVerdict } from "./verdict.js";
import { committeeReport } from "./report.js";
import { socialAuthenticity } from "../actionguard/socialauth.js";
import { searchWeb } from "../evidence/websearch.js";
import { chatJson } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";

/**
 * DYOR Research Agent — the signed, grounded deep-research report. It runs the crypto due-diligence
 * checklist a trader would spend 1-2 hours on (security, distribution, liquidity, smart-money, team,
 * social, news), but grounds every claim in on-chain truth + a live buy/sell simulation, cross-checks
 * the social buzz for shill-manufacturing, runs a bull-vs-bear AI committee, reflects on what's still
 * unverified (the deep-research loop), and SIGNS the whole thing. The promise: research you don't have
 * to double-check — because it's simulated, sourced, and cryptographically sealed.
 */

export type DyorSection = {
  dimension: string;
  status: "GOOD" | "CAUTION" | "BAD" | "INFO";
  finding: string; // plain-English
  evidence: { claim: string; source: string }[]; // click-through: claim → where it came from
};

export type DyorReport = {
  ok: boolean;
  observed_at: string;
  subject: { chain: string; address: string; name: string | null; symbol: string | null };
  recommendation: "BUY" | "HOLD" | "AVOID";
  conviction: "high" | "medium" | "low";
  confidence: number;
  bottom_line: string;
  sections: DyorSection[];
  bull_case: string;
  bear_case: string;
  open_questions: string[]; // gap-check: what a buyer should still verify
  sources: string[];
  method: { engines: string[]; models: { bull: string; bear: string; synthesizer: string } };
  signed: SignedReceipt | null;
  disclaimer: string;
};

const pct = (x: number | null | undefined) => (x == null ? "n/a" : (x * 100).toFixed(1) + "%");

export async function dyorReport(chain: ChainKey, address: string): Promise<DyorReport> {
  const observed_at = new Date().toISOString();
  // 1) gather full on-chain context (with live simulation) and fuse the verdict
  const ctx = await gather(chain, address, { sim: true });
  const verdict = await buildVerdict(ctx, "deep");
  const label = `${ctx.name ?? ctx.symbol ?? address}`;

  // 2) fan out the expensive/independent work in parallel; each degrades gracefully
  const [report, social, web] = await Promise.all([
    committeeReport(ctx, verdict),
    socialAuthenticity(ctx.symbol || ctx.name || address).catch(() => null),
    searchWeb(`${ctx.name ?? ""} ${ctx.symbol ?? ""} crypto token`.trim(), 4).catch(() => []),
  ]);
  const oc = report.onchain;

  // 3) assemble the DYOR checklist sections, grounded in the structured facts
  const sections: DyorSection[] = [];

  // Security — the fork simulation is the proof no static scanner has
  {
    const sev = oc.security.hard_flags.length > 0 || oc.security.honeypot ? "BAD" : (oc.security.sell_tax ?? 0) > 0.1 ? "CAUTION" : "GOOD";
    const ev: DyorSection["evidence"] = [];
    ev.push({ claim: oc.security.honeypot ? "sell simulation reverted — honeypot" : `sellable in live simulation (sell tax ${pct(oc.security.sell_tax)})`, source: "multi-vector buy/sell fork simulation" });
    for (const f of oc.security.hard_flags) ev.push({ claim: f, source: "security engine (hard flag)" });
    sections.push({ dimension: "Security", status: sev as any, finding: sev === "BAD" ? "Critical security risk — do not proceed." : sev === "CAUTION" ? "Sellable but with a meaningful tax/risk to weigh." : "Passed the live buy/sell simulation cleanly.", evidence: ev });
  }
  // Distribution / holders
  {
    const largest = oc.clusters?.largest_combined_pct ?? 0;
    const status = largest > 0.5 || (oc.smart_money?.dev_holding_percent ?? 0) > 0.3 ? "BAD" : largest > 0.2 ? "CAUTION" : "GOOD";
    sections.push({
      dimension: "Distribution", status,
      finding: status === "GOOD" ? "Supply looks broadly distributed." : "Concentration risk — a few entities hold a large share.",
      evidence: [
        { claim: `${(oc.token.holders ?? 0).toLocaleString()} holders`, source: "on-chain holder index" },
        { claim: `largest sybil cluster ${pct(largest)} of supply (${oc.clusters?.count ?? 0} clusters)`, source: "self-computed sybil clustering" },
        { claim: `dev holding ${pct(oc.smart_money?.dev_holding_percent)}`, source: "OKX Onchain OS" },
      ],
    });
  }
  // Liquidity & market
  {
    const liq = oc.market?.liquidity_usd ?? 0;
    // A MISSING FEED IS NOT A FINDING ABOUT THE ASSET.
    //
    // With no market data, `liq` fell back to 0 and 0 < 20_000, so the report graded the dimension
    // "BAD" — measured on USDT, whose own bottom_line in the same signed document called it "a deeply
    // liquid, broadly distributed, CEX-trusted stablecoin". The report contradicted itself because a
    // gap in our data was being scored as a defect in the token. The cheaper /verdict endpoint already
    // handles this correctly ("market-structure risk not applicable"), so the most expensive product
    // was the one that degraded worst.
    // "INFO" is the schema's existing non-judgement status — the point is that this dimension
    // carries no verdict at all, rather than a negative one.
    const status = !oc.market ? "INFO"
      : liq < 20_000 ? "BAD" : liq < 100_000 ? "CAUTION" : "GOOD";
    sections.push({
      dimension: "Liquidity & Market", status,
      finding: oc.market
        ? `$${liq.toLocaleString()} liquidity, $${(oc.market.volume_24h ?? 0).toLocaleString()} 24h volume.`
        : "No DEX market data was available for this token, so liquidity could not be assessed. This is "
          + "a gap in the available data, not evidence of poor liquidity — major assets that trade "
          + "primarily on centralised venues routinely have no DEX pair.",
      evidence: oc.market ? [
        { claim: `price $${oc.market.price_usd}, FDV ${oc.market.fdv ? "$" + oc.market.fdv.toLocaleString() : "n/a"}`, source: "DEX market data" },
        { claim: `${oc.market.buys_24h} buys / ${oc.market.sells_24h} sells (24h)`, source: "DEX market data" },
      ] : [],
    });
  }
  // Smart money & insider flow
  {
    const exit = oc.insider_flow?.exit_in_progress;
    const status = exit ? "BAD" : (oc.smart_money?.smart_money_signals ?? 0) > 0 ? "GOOD" : "INFO";
    sections.push({
      dimension: "Smart Money", status,
      finding: exit ? "Insiders are actively distributing (exit in progress)." : `${oc.smart_money?.smart_money_signals ?? 0} smart-money signals; concentration ${oc.smart_money?.cluster_concentration ?? "n/a"}.`,
      evidence: [
        { claim: `smart-money signals: ${oc.smart_money?.smart_money_signals ?? "n/a"}`, source: "OKX Onchain OS" },
        ...(oc.insider_flow ? [{ claim: `insiders distributed ${pct(oc.insider_flow.aggregate_distributed_pct)} of holdings (${oc.insider_flow.actively_distributing} actively selling)`, source: "insider-flow tracing" }] : []),
      ],
    });
  }
  // Team / deployer
  {
    const d = oc.deployer;
    const status = d ? (d.funded_by_mixer || (d.prior_malicious_contracts ?? 0) > 0 || d.malicious_flags.length > 0 ? "BAD" : "GOOD") : "INFO";
    sections.push({
      dimension: "Team / Deployer", status,
      finding: !d ? "Deployer not resolved." : status === "BAD" ? "Deployer has red flags — mixer funding or prior malicious contracts." : "Deployer wallet shows no known red flags.",
      evidence: d ? [
        { claim: `deployer ${d.creator ?? "?"} (${d.tx_count ?? "?"} txns)`, source: "on-chain deployer trace" },
        { claim: `funded by mixer: ${d.funded_by_mixer}; prior malicious contracts: ${d.prior_malicious_contracts ?? 0}`, source: "deployer forensics" },
        ...(d.malicious_flags.length ? [{ claim: `flags: ${d.malicious_flags.join(", ")}`, source: "GoPlus address security" }] : []),
      ] : [],
    });
  }
  // Social & narrative — the shill-authenticity check nobody else has
  {
    const status = social ? (social.verdict === "MANUFACTURED_HYPE" ? "BAD" : social.verdict === "ORGANIC" ? "GOOD" : "INFO") : "INFO";
    sections.push({
      dimension: "Social & Narrative", status,
      finding: !social ? "No social signal available." : social.verdict === "MANUFACTURED_HYPE" ? `Buzz looks manufactured (authenticity ${social.authenticity_score}/100) — likely coordinated shilling.` : social.verdict === "ORGANIC" ? `Buzz looks organic (authenticity ${social.authenticity_score}/100).` : "Not enough social chatter to judge.",
      evidence: social ? [{ claim: `authenticity ${social.authenticity_score}/100, buzz ${social.buzz_score}/100 → ${social.verdict}`, source: "Aletheia social-authenticity engine (X/Reddit/YouTube)" }] : [],
    });
  }
  // News / web
  {
    const status = web.length ? "INFO" : "INFO";
    sections.push({
      dimension: "News / Web", status,
      finding: web.length ? `${web.length} relevant sources found.` : "No notable web coverage found.",
      evidence: web.slice(0, 4).map((s: any) => ({ claim: s.title || s.url, source: s.url })),
    });
  }

  // 4) gap-check reflection (the deep-research loop): what remains unverified?
  let open_questions: string[] = [];
  try {
    const gc = await chatJson<{ open_questions: string[] }>(
      [
        { role: "system", content: "You are a due-diligence reviewer. Given a token's completed research sections, list 2-4 SHORT specific questions a buyer should still verify themselves that the data did not fully answer (e.g. lock expiry, team identity, roadmap delivery). Return JSON {open_questions: string[]}. Ground them in gaps in the provided data — do not invent facts." },
        { role: "user", content: JSON.stringify({ subject: label, recommendation: report.recommendation, sections: sections.map((s) => ({ d: s.dimension, status: s.status, finding: s.finding })) }) },
      ],
      { tier: "strong", maxTokens: 300, temperature: 0.3 }
    );
    if (Array.isArray(gc.data?.open_questions)) open_questions = gc.data.open_questions.slice(0, 4).map((q) => String(q).slice(0, 200));
  } catch { /* non-fatal */ }
  // Deterministic fallback — the "what to still verify yourself" list must never be empty. These are the
  // DYOR unknowns on-chain data structurally can't answer, tailored to what this token's data left open.
  if (open_questions.length === 0) {
    const q: string[] = [];
    if (!ctx.established) q.push("Is the team public/doxxed, or is the deployer anonymous?");
    q.push("Is the liquidity locked, and if so, when does the lock expire?");
    if ((sections.find((s) => s.dimension === "Social & Narrative")?.status ?? "INFO") !== "GOOD") q.push("Is there genuine community traction, or is the buzz too thin/manufactured to tell?");
    q.push("Does the project deliver real utility beyond the token, and is the contract audited and open-source?");
    open_questions = q.slice(0, 4);
  }

  // 5) assemble, collect sources, and SIGN the whole report
  const sources = [...new Set([...web.map((s: any) => s.url).filter(Boolean), "on-chain (fork simulation + holder/deployer trace)", "OKX Onchain OS", "GoPlus", ...(social ? ["social: X/Reddit/YouTube"] : [])])];
  const subject = { chain, address, name: ctx.name ?? null, symbol: ctx.symbol ?? null };
  const signed = await signReceipt({
    kind: "dyor_report", subject, recommendation: report.recommendation, conviction: report.conviction,
    confidence: verdict.confidence, sections: sections.map((s) => ({ d: s.dimension, status: s.status })), observed_at,
  });

  return {
    ok: true, observed_at, subject,
    recommendation: report.recommendation,
    conviction: report.conviction,
    confidence: verdict.confidence,
    bottom_line: report.bottom_line,
    sections,
    bull_case: report.bull_case,
    bear_case: report.bear_case,
    open_questions,
    sources,
    method: { engines: ["fork-simulation", "Slither/GoPlus security", "sybil clustering", "deployer forensics", "OKX Onchain OS", "social-authenticity", "web search", "multi-model committee"], models: { bull: report.debate.bull_model, bear: report.debate.bear_model, synthesizer: report.debate.synthesizer_model } },
    signed,
    disclaimer: "Aletheia DYOR is grounded, signed decision-support — not financial advice. Verify the open questions yourself before acting.",
  };
}
