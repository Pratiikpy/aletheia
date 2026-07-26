import { alchemyRpc, type ChainKey } from "../config.js";
import { searchWeb, readPage, type Source } from "../evidence/websearch.js";
import { socialPulse } from "../pulse/pulse.js";
import { chat, chatJson } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";
import { dyorReport } from "./dyor.js";
import { walletReport } from "./walletreport.js";
import { solanaVerdict } from "./solana.js";
import { deepResearch } from "./deepresearch.js";

/**
 * Research on ANYTHING — the subject-agnostic front door. Hand it a token, a wallet, a Solana mint, a
 * URL, or a plain-text topic/claim/narrative, and it auto-detects what it is and runs the right deep
 * investigation. Tokens/wallets/Solana route to the on-chain engines; everything else (a topic, a
 * narrative, a claim, a question) runs a grounded web + social + multi-AI committee investigation and is
 * signed. Same principle throughout: gather real evidence, let a jury argue it, prove the answer.
 */

const EVM = /^0x[a-fA-F0-9]{40}$/;
const SOL = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const URLRE = /^https?:\/\//i;

export type TopicResearch = {
  ok: boolean;
  observed_at: string;
  topic: string;
  stance: "SUPPORTED" | "MIXED" | "UNSUPPORTED" | "MANUFACTURED_HYPE" | "UNCLEAR";
  confidence: number;
  bottom_line: string;
  bull_case: string;
  bear_case: string;
  key_points: string[];
  risks: string[];
  social: { label: string; sentiment: string; authenticity: string; red_flags: string[] } | null;
  sources: { title: string; url: string }[];
  open_questions: string[];
  signed: SignedReceipt | null;
  disclaimer: string;
};

/** Does this EVM address have contract code? (contract → token research; EOA → wallet research) */
async function hasCode(chain: ChainKey, addr: string): Promise<boolean> {
  try {
    const res = await fetch(alchemyRpc(chain), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [addr, "latest"] }),
      signal: AbortSignal.timeout(30_000),
    });
    const j: any = await res.json();
    const code = j?.result ?? "0x";
    return typeof code === "string" && code.length > 2;
  } catch {
    return false; // can't tell → treat as wallet (safer default for an address)
  }
}

/** Deep research on a free-text topic, narrative, claim, or a URL — grounded, argued, signed. */
export async function topicResearch(topic: string, opts: { seedUrl?: string } = {}): Promise<TopicResearch> {
  const observed_at = new Date().toISOString();
  const q = topic.trim();

  // 1) gather evidence in parallel: web search + live social chatter (+ read a seed URL if given)
  const [web, pulse, seed] = await Promise.all([
    searchWeb(q, 5).catch((): Source[] => []),
    socialPulse(q).catch(() => null),
    opts.seedUrl ? readPage(opts.seedUrl, 3500).catch(() => "") : Promise.resolve(""),
  ]);

  // read the top 2 web sources for real content (not just snippets)
  const reads = await Promise.all(
    web.slice(0, 2).map((s) => readPage(s.url, 2500).catch(() => "")),
  );

  // 2) build a grounded fact sheet — models may ONLY use this
  const lines: string[] = [`TOPIC / CLAIM: ${q}`];
  if (seed) lines.push(`\nSOURCE PAGE (${opts.seedUrl}):\n${seed.slice(0, 1600)}`);
  if (web.length) {
    lines.push("\nWEB FINDINGS:");
    web.forEach((s, i) => lines.push(`- ${s.title} — ${s.snippet}${reads[i] ? `\n  excerpt: ${reads[i].slice(0, 500)}` : ""} [${s.url}]`));
  } else lines.push("\nWEB FINDINGS: none found.");
  if (pulse) lines.push(`\nSOCIAL (X/Reddit/YouTube): ${pulse.label}, sentiment ${pulse.sentiment}, buzz ${pulse.buzz_score}/100. ${pulse.rationale} Red flags: ${JSON.stringify(pulse.red_flags)}.`);
  else lines.push("\nSOCIAL: no signal.");
  const facts = lines.join("\n");

  const rules = "You are a research analyst. Use ONLY the evidence provided — never invent facts, sources, numbers, or events. If the evidence doesn't support a claim, say so plainly.";

  // 3) bull vs bear argue from the same evidence (different models)
  const [bull, bear] = await Promise.all([
    chat([{ role: "system", content: rules + " You are the BULL/PRO side. Make the strongest HONEST case that the claim/topic is TRUE or positive, grounded only in the evidence. 3-5 sentences." }, { role: "user", content: facts }], { tier: "strong", maxTokens: 420, temperature: 0.3 }).catch(() => ({ content: "" } as any)),
    chat([{ role: "system", content: rules + " You are the BEAR/SKEPTIC side. Make the strongest HONEST case AGAINST the claim/topic, or that the buzz is manufactured, grounded only in the evidence. 3-5 sentences." }, { role: "user", content: facts }], { tier: "alt", maxTokens: 420, temperature: 0.3 }).catch(() => ({ content: "" } as any)),
  ]);

  // 4) synthesizer → structured verdict
  let data: Partial<{ stance: string; confidence: number; bottom_line: string; key_points: string[]; risks: string[]; open_questions: string[] }> = {};
  try {
    const res = await chatJson<typeof data>(
      [
        { role: "system", content: rules + ` Synthesize the two sides into JSON: stance (one of "SUPPORTED"|"MIXED"|"UNSUPPORTED"|"MANUFACTURED_HYPE"|"UNCLEAR"), confidence (0..1), bottom_line (1-2 sentences), key_points (string[]), risks (string[]), open_questions (2-4 short things a reader should still verify themselves). Base everything only on the evidence.` },
        { role: "user", content: `${facts}\n\nPRO:\n${bull.content}\n\nSKEPTIC:\n${bear.content}` },
      ],
      { tier: "strong", maxTokens: 1100, temperature: 0.2 }
    );
    data = res.data ?? {};
  } catch { /* fall back below */ }

  const stance = (["SUPPORTED", "MIXED", "UNSUPPORTED", "MANUFACTURED_HYPE", "UNCLEAR"].includes(String(data.stance)) ? data.stance : (pulse?.label === "HYPE" ? "MANUFACTURED_HYPE" : "UNCLEAR")) as TopicResearch["stance"];
  const open_questions = Array.isArray(data.open_questions) && data.open_questions.length
    ? data.open_questions.slice(0, 4).map((x) => String(x).slice(0, 200))
    : ["Is there a primary source (official announcement / on-chain proof) behind this?", "Is the discussion organic, or concentrated in a few coordinated accounts?"];

  const social = pulse ? {
    label: pulse.label,
    sentiment: pulse.sentiment,
    authenticity: pulse.label === "HYPE" ? "looks manufactured / promotional" : pulse.label === "ORGANIC" ? "looks organic" : "too little chatter to tell",
    red_flags: pulse.red_flags ?? [],
  } : null;
  const sources = web.map((s) => ({ title: s.title, url: s.url }));

  const signed = await signReceipt({ kind: "topic_research", topic: q.slice(0, 300), stance, confidence: Number((data.confidence ?? 0.5).toFixed(2)), sources: sources.map((s) => s.url), observed_at });

  return {
    ok: true, observed_at, topic: q, stance,
    confidence: Number((data.confidence ?? 0.5).toFixed(2)),
    bottom_line: data.bottom_line ?? (bull.content || bear.content || "Not enough evidence to reach a firm conclusion."),
    bull_case: bull.content, bear_case: bear.content,
    key_points: Array.isArray(data.key_points) ? data.key_points : [],
    risks: Array.isArray(data.risks) ? data.risks : [],
    social, sources, open_questions, signed,
    disclaimer: "Grounded research, not financial advice. Verify the open questions yourself before acting.",
  };
}

export type ResearchResult = {
  ok: boolean;
  observed_at: string;
  subject: string;
  subject_type: "token" | "wallet" | "solana_token" | "topic" | "url" | "repo";
  report: unknown;
  error?: string;
};

/** The router: auto-detect the subject and run the right deep investigation. */
export async function researchAnything(subject: unknown, chain: ChainKey = "ethereum"): Promise<ResearchResult> {
  const observed_at = new Date().toISOString();
  const s = String(subject ?? "").trim();
  const wrap = (subject_type: ResearchResult["subject_type"], report: unknown): ResearchResult => ({ ok: true, observed_at, subject: s.slice(0, 200), subject_type, report });

  try {
    if (EVM.test(s)) {
      const contract = await hasCode(chain, s);
      return contract ? wrap("token", await dyorReport(chain, s)) : wrap("wallet", await walletReport(chain, s));
    }
    if (/github\.com\//i.test(s)) {
      const { repoRadar } = await import("../repo/radar.js");
      return wrap("repo", await repoRadar(s));
    }
    if (URLRE.test(s)) return wrap("url", await deepResearch(s, { seedUrl: s }));
    if (SOL.test(s)) return wrap("solana_token", await solanaVerdict(s, "full"));
    if (s) return wrap("topic", await deepResearch(s));
    return { ok: false, observed_at, subject: "", subject_type: "topic", report: null, error: "empty subject" };
  } catch (e: any) {
    return { ok: false, observed_at, subject: s.slice(0, 200), subject_type: "topic", report: null, error: e?.message ?? String(e) };
  }
}
