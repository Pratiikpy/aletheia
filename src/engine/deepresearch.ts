import { searchWeb, readPage, type Source } from "../evidence/websearch.js";
import { socialPulse } from "../pulse/pulse.js";
import { chat, chatJson } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";

/**
 * Deep Research core — best-in-class, subject-agnostic. It combines the techniques that make the leading
 * open-source deep-research agents strong, and adds the one thing none of them have (signed provenance):
 *   1. Query decomposition        — a planner splits the subject into sub-questions (gpt-researcher)
 *   2. Multi-source gather         — search every sub-question, dedup, ~15-20 sources (gpt-researcher)
 *   3. Credibility ranking         — weight sources by domain reputation (poisoning defence)
 *   4. Full-page read + compress   — read the top sources in full, summarise per-source (smolagents)
 *   5. Iterative deepening         — a reflection pass emits follow-up queries → round 2 (dzhng/jina)
 *   6. Cited synthesis             — every finding must cite source ids; unsupported claims dropped
 *   7. Corroboration               — findings backed by <2 sources flagged as single-source
 *   8. Signed citation graph       — the claim→source map is hashed + EIP-191 signed (our moat)
 */

export type Cite = { id: number; url: string; title: string; snippet: string; credibility: number };
export type Finding = { claim: string; citations: { n: number; url: string }[]; corroboration: "corroborated" | "single-source" };
export type DeepResearch = {
  ok: boolean;
  observed_at: string;
  question: string;
  stance: "SUPPORTED" | "MIXED" | "UNSUPPORTED" | "MANUFACTURED_HYPE" | "UNCLEAR";
  confidence: number;
  answer: string;
  bottom_line: string;
  findings: Finding[];
  sources: { n: number; url: string; title: string; credibility: number }[];
  social: { label: string; sentiment: string; authenticity: string } | null;
  open_questions: string[];
  sub_questions: string[];
  rounds: number;
  signed: SignedReceipt | null;
  disclaimer: string;
};

/** Domain-reputation weighting — high-trust primary/official/major sources up-weighted, UGC down-weighted. */
function credibility(url: string): number {
  try {
    const h = new URL(url).host.replace(/^www\./, "").toLowerCase();
    const hi = ["reuters.com", "bloomberg.com", "apnews.com", "coindesk.com", "theblock.co", "cointelegraph.com", "etherscan.io", "arbiscan.io", "dune.com", "messari.io", "coingecko.com", "coinmarketcap.com", "defillama.com", "binance.com", "okx.com", "wikipedia.org", "github.com", "docs.", ".gov", ".edu"];
    const lo = ["reddit.com", "medium.com", "x.com", "twitter.com", "t.me", "telegram", "blogspot", "substack.com", "quora.com"];
    if (hi.some((d) => h.includes(d))) return 0.9;
    if (lo.some((d) => h.includes(d))) return 0.45;
    return 0.65;
  } catch { return 0.5; }
}

/** search every query, flatten, dedup by URL. */
async function gather(queries: string[], perQuery = 4): Promise<Source[]> {
  const results = await Promise.all(queries.map((qq) => searchWeb(qq, perQuery).catch(() => [] as Source[])));
  const seen = new Set<string>();
  const out: Source[] = [];
  for (const s of results.flat()) {
    if (!s?.url || seen.has(s.url)) continue;
    seen.add(s.url);
    out.push(s);
  }
  return out;
}

/** rank by credibility, read the top N pages in full, compress into cited source cards (continuing ids). */
async function ingest(sources: Source[], startId: number, n: number): Promise<Cite[]> {
  const ranked = [...sources].sort((a, b) => credibility(b.url) - credibility(a.url)).slice(0, n);
  const cites = await Promise.all(ranked.map(async (s) => {
    const page = await readPage(s.url, 2200).catch(() => "");
    return { id: 0, url: s.url, title: s.title, snippet: (page || s.snippet || "").replace(/\s+/g, " ").slice(0, 900), credibility: credibility(s.url) } as Cite;
  }));
  cites.forEach((c, i) => (c.id = startId + i));
  return cites;
}

export async function deepResearch(question: string, opts: { seedUrl?: string; maxDepth?: number } = {}): Promise<DeepResearch> {
  const observed_at = new Date().toISOString();
  const q = question.trim();
  const maxDepth = Math.max(1, Math.min(3, opts.maxDepth ?? 2));

  // 1) PLAN — decompose the subject into sub-questions (perspective-diverse)
  let sub_questions: string[] = [];
  try {
    const plan = await chatJson<{ sub_questions: string[] }>(
      [
        { role: "system", content: "You are a research planner. Break the user's question or topic into 4-6 SPECIFIC, non-overlapping sub-questions whose answers together fully address it — covering different angles (facts/claims, evidence for, evidence against, context, red flags). Return JSON {sub_questions: string[]}." },
        { role: "user", content: q },
      ],
      { tier: "strong", maxTokens: 800, temperature: 0.3 }
    );
    sub_questions = (plan.data?.sub_questions ?? []).map((s) => String(s)).filter(Boolean).slice(0, 6);
  } catch { /* fall back to a deterministic decomposition below */ }
  // If the planner failed or under-decomposed (e.g. truncated JSON), never collapse to a single
  // question — synthesize perspective-diverse angles so research always covers multiple lenses.
  if (sub_questions.length < 2) {
    sub_questions = [
      `Core verifiable facts: ${q}`,
      `Strongest evidence in favor — ${q}`,
      `Strongest evidence against, and any red flags — ${q}`,
      `Relevant context, history, or track record — ${q}`,
    ];
  }

  // 2-4) GATHER → rank → read-in-full (round 1), in parallel with the social read
  const [round1, pulse, seed] = await Promise.all([
    gather(sub_questions, 4),
    socialPulse(q).catch(() => null),
    opts.seedUrl ? readPage(opts.seedUrl, 2500).catch(() => "") : Promise.resolve(""),
  ]);
  let cites = await ingest(round1, 1, 6);
  if (seed && opts.seedUrl) cites.unshift({ id: 0, url: opts.seedUrl, title: "(the linked page)", snippet: seed.replace(/\s+/g, " ").slice(0, 900), credibility: credibility(opts.seedUrl) });
  cites.forEach((c, i) => (c.id = i + 1)); // renumber after any unshift
  let rounds = 1;

  // 5) ITERATIVE DEEPENING — reflect on gaps, run one follow-up round if needed
  if (maxDepth >= 2) {
    try {
      const reflect = await chatJson<{ enough: boolean; follow_ups: string[] }>(
        [
          { role: "system", content: "Given the QUESTION and the source excerpts so far, decide if there is enough to answer it well and completely. Return JSON {enough: boolean, follow_ups: string[] (0-3 NEW, specific search queries that would fill the biggest remaining gaps — empty if enough)}." },
          { role: "user", content: `QUESTION: ${q}\n\nSOURCES SO FAR:\n${cites.map((c) => `[${c.id}] ${c.title}: ${c.snippet.slice(0, 260)}`).join("\n")}` },
        ],
        { tier: "strong", maxTokens: 300, temperature: 0.3 }
      );
      const followUps = (reflect.data?.follow_ups ?? []).map((s) => String(s)).filter(Boolean).slice(0, 3);
      if (!reflect.data?.enough && followUps.length) {
        const more = await gather(followUps, 3);
        const fresh = more.filter((s) => !cites.some((c) => c.url === s.url));
        const extra = await ingest(fresh, cites.length + 1, 4);
        cites = [...cites, ...extra];
        rounds = 2;
      }
    } catch { /* non-fatal — proceed with round 1 */ }
  }

  // 6) CITED SYNTHESIS — every finding must cite source ids; unsupported claims are dropped
  const socialLine = pulse ? `SOCIAL SIGNAL (X/Reddit/YouTube): ${pulse.label}, sentiment ${pulse.sentiment}, buzz ${pulse.buzz_score}/100. Red flags: ${JSON.stringify(pulse.red_flags ?? [])}.` : "SOCIAL SIGNAL: none.";
  const sourceBlock = cites.map((c) => `[${c.id}] (${(c.credibility * 100).toFixed(0)}% cred · ${c.title}) ${c.url}\n${c.snippet}`).join("\n\n");
  let syn: any = {};
  try {
    const res = await chatJson<any>(
      [
        { role: "system", content: "You are Aletheia, a rigorous research analyst. Using ONLY the numbered sources and the social signal, produce a grounded, cited answer. NEVER invent facts, numbers, partnerships, or events. Return JSON: {answer (2-4 sentences, the direct answer), stance (one of SUPPORTED|MIXED|UNSUPPORTED|MANUFACTURED_HYPE|UNCLEAR), confidence (0..1), findings: [{claim: string, sources: number[] (the [n] source ids that support THIS claim — every finding MUST cite >=1 id; drop any claim you cannot cite)}] (5-8 findings; prefer claims supported by 2+ sources), bottom_line (1-2 sentences), open_questions (2-4 things the reader should still verify themselves)}." },
        { role: "user", content: `QUESTION: ${q}\n\n${socialLine}\n\nNUMBERED SOURCES:\n${sourceBlock}` },
      ],
      { tier: "strong", maxTokens: 2800, temperature: 0.2 }
    );
    syn = res.data ?? {};
  } catch { /* degrade below */ }

  // 7) CORROBORATION — resolve cited ids, flag single-source findings
  const byId = new Map(cites.map((c) => [c.id, c]));
  const findings: Finding[] = (Array.isArray(syn.findings) ? syn.findings : [])
    .map((f: any) => {
      const ids: number[] = Array.isArray(f?.sources) ? f.sources.map((n: any) => Number(n)).filter((n: number) => byId.has(n)) : [];
      return {
        claim: String(f?.claim ?? "").slice(0, 400),
        citations: ids.map((n) => ({ n, url: byId.get(n)!.url })),
        corroboration: ids.length >= 2 ? "corroborated" : "single-source",
      } as Finding;
    })
    .filter((f: Finding) => f.claim && f.citations.length > 0); // drop uncited claims

  const stance = (["SUPPORTED", "MIXED", "UNSUPPORTED", "MANUFACTURED_HYPE", "UNCLEAR"].includes(String(syn.stance)) ? syn.stance : (pulse?.label === "HYPE" ? "MANUFACTURED_HYPE" : "UNCLEAR")) as DeepResearch["stance"];
  const confidence = Number((typeof syn.confidence === "number" ? syn.confidence : 0.5).toFixed(2));
  const open_questions = (Array.isArray(syn.open_questions) && syn.open_questions.length ? syn.open_questions : ["Is there a primary/official source behind this?", "Is the evidence corroborated across independent sources, or concentrated in one?"]).slice(0, 4).map((x: any) => String(x).slice(0, 200));

  // 8) SIGN THE CITATION GRAPH — the signature attests provenance, not just prose
  const citation_graph = findings.map((f) => ({ claim: f.claim.slice(0, 180), sources: f.citations.map((c) => c.url) }));
  const signed = await signReceipt({ kind: "deep_research", question: q.slice(0, 300), stance, confidence, citation_graph, rounds, observed_at });

  return {
    ok: true, observed_at, question: q, stance, confidence,
    answer: String(syn.answer ?? "").slice(0, 900) || "Not enough grounded evidence to answer confidently.",
    bottom_line: String(syn.bottom_line ?? syn.answer ?? "").slice(0, 500),
    findings,
    sources: cites.map((c) => ({ n: c.id, url: c.url, title: c.title, credibility: c.credibility })),
    social: pulse ? { label: pulse.label, sentiment: pulse.sentiment, authenticity: pulse.label === "HYPE" ? "looks manufactured / promotional" : pulse.label === "ORGANIC" ? "looks organic" : "too little chatter to tell" } : null,
    open_questions, sub_questions, rounds, signed,
    disclaimer: "Grounded, cited, multi-round research — not financial advice. Every claim links to its source; verify the open questions yourself.",
  };
}
