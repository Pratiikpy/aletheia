import type { RawContext } from "./context.js";
import type { Verdict, Signal } from "../types/verdict.js";
import { chat, chatJson } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";

/**
 * Deep-tier committee report (A2A escrow product) — the analyst-committee pattern.
 * A bull and a bear argue from the SAME evidence (different 0G models), then a synthesizer produces
 * a structured, grounded report. Discipline: models may ONLY use provided facts — no invention.
 */

/** The complete structured on-chain fact-set — the raw data an agent gets from a data-explorer AND
 * the risk read it gets from a scanner, in ONE call. Every field is machine-usable, not prose. */
export type OnchainFacts = {
  token: { name: string | null; symbol: string | null; chain: string; address: string; established: boolean; holders: number };
  market: { price_usd: number | string | null; liquidity_usd: number; volume_24h: number; buys_24h: number; sells_24h: number; fdv: number | null } | null;
  security: { simulated: boolean; honeypot: boolean | null; buy_tax: number | null; sell_tax: number | null; hard_flags: string[] };
  smart_money: Verdict["okx_metrics"];
  deployer: { creator: string | null; tx_count: number | null; funded_by_mixer: boolean; malicious_flags: string[]; prior_malicious_contracts: number | null } | null;
  insider_flow: { wallets_tracked: number; actively_distributing: number; aggregate_distributed_pct: number; exit_in_progress: boolean } | null;
  clusters: { count: number; largest_combined_pct: number } | null;
};

export type CommitteeReport = {
  recommendation: "BUY" | "HOLD" | "AVOID";
  conviction: "high" | "medium" | "low";
  bull_case: string;
  bear_case: string;
  key_strengths: string[];
  key_risks: string[];
  bottom_line: string;
  onchain: OnchainFacts; // full structured on-chain data + risk facts (beats a raw data-explorer AND a scanner)
  debate: { bull_model: string; bear_model: string; synthesizer_model: string };
  signed: SignedReceipt | null; // EIP-191 signature over the report's decisive fields — provable, offline-verifiable
  generated_at: string;
};

/** Assemble the full structured on-chain fact-set from the gathered context + fused verdict. */
function buildOnchainFacts(ctx: RawContext, verdict: Verdict): OnchainFacts {
  const m = ctx.market.topPair;
  const d = ctx.deployer;
  const f = ctx.insiderFlow;
  const cl = ctx.insiderCluster;
  return {
    token: { name: ctx.name ?? null, symbol: ctx.symbol ?? null, chain: ctx.chain, address: verdict.subject.address, established: ctx.established, holders: ctx.holderCount },
    market: m ? { price_usd: m.priceUsd ?? null, liquidity_usd: Math.round(ctx.market.totalLiquidityUsd), volume_24h: Math.round(m.volumeH24), buys_24h: m.txnsH24Buys, sells_24h: m.txnsH24Sells, fdv: m.fdv ?? null } : null,
    security: { simulated: !!ctx.sim?.simulated, honeypot: ctx.sim?.isHoneypot ?? null, buy_tax: ctx.sim?.maxBuyTax ?? null, sell_tax: ctx.sim?.maxSellTax ?? null, hard_flags: verdict.signals.filter((s) => s.is_hard_flag).map((s) => s.finding) },
    smart_money: verdict.okx_metrics,
    deployer: d && d.ok ? { creator: d.creator, tx_count: d.txCount, funded_by_mixer: d.funderIsMixer, malicious_flags: d.maliciousFlags, prior_malicious_contracts: d.maliciousContractsCreated } : null,
    insider_flow: f && f.ok ? { wallets_tracked: f.walletsTracked, actively_distributing: f.activelyDistributing, aggregate_distributed_pct: f.aggregateDistributedPct, exit_in_progress: f.activelyDistributing > 0 && f.aggregateDistributedPct > 0.2 } : null,
    clusters: cl ? { count: cl.clusters.length, largest_combined_pct: cl.clusters.reduce((mx, c) => Math.max(mx, c.combinedPercent), 0) } : null,
  };
}

function factSheet(ctx: RawContext, verdict: Verdict): string {
  const m = ctx.market.topPair;
  const lines: string[] = [];
  lines.push(`Token: ${ctx.name ?? verdict.subject.address} (${ctx.symbol ?? "?"}) on ${ctx.chain}`);
  lines.push(`Aletheia fused verdict: ${verdict.verdict} (score ${verdict.score}/100, confidence ${(verdict.confidence * 100).toFixed(0)}%)`);
  lines.push(`Established/CEX-listed: ${ctx.established ? "yes" : "no"}; holders: ${ctx.holderCount.toLocaleString()}`);
  if (m) lines.push(`Market: price $${m.priceUsd ?? "?"}, liquidity $${Math.round(ctx.market.totalLiquidityUsd).toLocaleString()}, 24h vol $${Math.round(m.volumeH24).toLocaleString()}, buys/sells ${m.txnsH24Buys}/${m.txnsH24Sells}, FDV ${m.fdv ? "$" + Math.round(m.fdv).toLocaleString() : "?"}`);
  if (ctx.sim?.simulated) lines.push(`Simulation: honeypot=${ctx.sim.isHoneypot}, maxBuyTax=${pct(ctx.sim.maxBuyTax)}, maxSellTax=${pct(ctx.sim.maxSellTax)}`);
  lines.push("Findings:");
  for (const s of verdict.signals) lines.push(`  - [sev ${s.severity}/5${s.is_hard_flag ? ", HARD" : ""}] ${s.finding}`);
  return lines.join("\n");
}
const pct = (x: number | null | undefined) => (x == null ? "?" : (x * 100).toFixed(1) + "%");

export async function committeeReport(ctx: RawContext, verdict: Verdict): Promise<CommitteeReport> {
  const facts = factSheet(ctx, verdict);
  const rules =
    "You are part of a pre-trade research committee. Use ONLY the facts provided — never invent numbers, partnerships, roadmap, or claims not present. If the facts don't support a case, say so plainly.";

  // Bull and bear argue in parallel from the same evidence, using different models.
  const [bull, bear] = await Promise.all([
    chat([{ role: "system", content: rules + " You are the BULL. Make the strongest HONEST case FOR buying, grounded in the facts. 3-5 sentences." }, { role: "user", content: facts }], { tier: "strong", maxTokens: 500, temperature: 0.3 }).catch(() => ({ content: "", model: "n/a" })),
    chat([{ role: "system", content: rules + " You are the BEAR. Make the strongest HONEST case AGAINST buying, grounded in the facts. 3-5 sentences." }, { role: "user", content: facts }], { tier: "alt", maxTokens: 500, temperature: 0.3 }).catch(() => ({ content: "", model: "n/a" })),
  ]);

  // Synthesizer produces the structured report. Resilient: if the model truncates or returns
  // non-JSON, degrade gracefully to a report built from the bull/bear text + verdict (never 500).
  let data: Partial<Omit<CommitteeReport, "debate" | "generated_at">> = {};
  let model = "fallback";
  try {
    const res = await chatJson<Omit<CommitteeReport, "debate" | "generated_at">>(
      [
        { role: "system", content: rules + ` Synthesize the bull and bear into a final JSON report with keys: recommendation ("BUY"|"HOLD"|"AVOID"), conviction ("high"|"medium"|"low"), bull_case (string), bear_case (string), key_strengths (string[]), key_risks (string[]), bottom_line (string, 1-2 sentences). Respect Aletheia's verdict (${verdict.verdict}) unless the facts clearly contradict it.` },
        { role: "user", content: `${facts}\n\nBULL:\n${bull.content}\n\nBEAR:\n${bear.content}` },
      ],
      { tier: "strong", maxTokens: 1200, temperature: 0.2 }
    );
    data = res.data; model = res.model;
  } catch { /* synthesizer failed → fall back to bull/bear + verdict via the defaults below */ }

  const recommendation = (data.recommendation as any) ?? (verdict.verdict === "GO" ? "BUY" : verdict.verdict === "AVOID" ? "AVOID" : "HOLD");
  const conviction = (data.conviction as any) ?? "medium";
  const onchain = buildOnchainFacts(ctx, verdict);
  const generated_at = new Date().toISOString();
  // Sign the decisive fields + the raw on-chain facts so any caller verifies the whole report offline —
  // change one number and the signature breaks. This is provable on-chain intelligence, not a prose blob.
  const signed = await signReceipt({ kind: "onchain_intel", chain: ctx.chain, address: verdict.subject.address, verdict: verdict.verdict, score: verdict.score, recommendation, conviction, onchain, generated_at });

  return {
    recommendation,
    conviction,
    bull_case: data.bull_case ?? bull.content,
    bear_case: data.bear_case ?? bear.content,
    key_strengths: Array.isArray(data.key_strengths) ? data.key_strengths : [],
    key_risks: Array.isArray(data.key_risks) ? data.key_risks : [],
    bottom_line: data.bottom_line ?? verdict.summary,
    onchain,
    debate: { bull_model: bull.model, bear_model: bear.model, synthesizer_model: model },
    signed,
    generated_at,
  };
}
