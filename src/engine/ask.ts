import { verityCheck } from "./check.js";
import { searchWeb, readPage } from "../evidence/websearch.js";
import { chat, juryConsensus } from "../ai/router.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";
import type { ChainKey } from "../config.js";
import { createHash } from "node:crypto";

/**
 * Ask Aletheia — the simple front door. Ask ONE question in plain language and the agent uses whatever
 * power the question needs: it pulls any address/token in the question through the on-chain safety check,
 * reads any linked page, grounds the answer in a live web search, synthesizes a direct answer with inline
 * sources — then runs its OWN multi-model jury to verify the answer isn't hallucinated, and signs the
 * whole thing. One question in, a grounded, jury-checked, provable answer out.
 */

export type AskResult = {
  ok: boolean;
  observed_at: string;
  question: string;
  answer: string;
  jury: { verdict: string; confidence: number; agreement: number; models: number } | null; // our jury's read on our own answer
  powers_used: string[];
  sources: { title: string; url: string }[];
  signed: SignedReceipt | null;
  disclaimer: string;
};

const EVM = /0x[a-fA-F0-9]{40}/;
const URLRE = /https?:\/\/[^\s)]+/;

export async function askAletheia(question: string, chain: ChainKey = "ethereum"): Promise<AskResult> {
  const observed_at = new Date().toISOString();
  const q = String(question ?? "").trim();
  const used: string[] = [];
  const facts: string[] = [];

  // 1) if the question names an on-chain address, run it through the safety check (Krisis)
  const evm = q.match(EVM);
  if (evm) {
    used.push("on-chain safety check");
    const c: any = await verityCheck(evm[0], chain).catch(() => null);
    if (c) facts.push(`Aletheia on-chain check of ${evm[0]} → ${c.decision} (${Math.round((c.confidence || 0) * 100)}% confidence). ${c.narration}`);
  }
  // 2) if it links a page, read it
  const url = q.match(URLRE);
  if (url) {
    const page = await readPage(url[0], 2500).catch(() => "");
    if (page) { used.push("read linked page"); facts.push(`Content of ${url[0]}:\n${page.slice(0, 1300)}`); }
  }
  // 3) always ground in a live web search (+ read the top couple pages)
  const web = await searchWeb(q, 4).catch(() => [] as any[]);
  if (web.length) {
    used.push("live web search");
    web.forEach((s: any) => facts.push(`${s.title} — ${s.snippet} [${s.url}]`));
    const reads = await Promise.all(web.slice(0, 2).map((s: any) => readPage(s.url, 1500).catch(() => "")));
    reads.forEach((r, i) => { if (r) facts.push(`Excerpt from ${web[i].url}: ${r.slice(0, 700)}`); });
  }

  const evidence = facts.join("\n\n") || "(no external evidence was available)";

  // 4) synthesize a direct, grounded answer with inline sources
  used.push("multi-model synthesis");
  const ans = await chat(
    [
      { role: "system", content: "You are Aletheia, a trust-focused research agent for the crypto/agent economy. Answer the user's question directly and honestly using ONLY the evidence provided plus well-established general knowledge. Write in PLAIN, NATURAL PROSE — roughly 60-140 words, NO markdown headers, NO '#', NO bullet symbols, just clear sentences. Cite a source inline as [url] when the evidence backs a specific claim. If the evidence is thin or you are unsure, say so plainly — never fabricate facts, numbers, partnerships, or events. Finish with one short sentence on what to still verify if it matters." },
      { role: "user", content: `QUESTION: ${q}\n\nEVIDENCE:\n${evidence}` },
    ],
    { tier: "strong", maxTokens: 1400, temperature: 0.3 }
  ).catch(() => ({ content: "" } as any));
  const answer = (ans.content || "").trim() || "I couldn't gather enough grounded evidence to answer this confidently — treat as unverified.";

  // 5) the jury verifies our OWN answer — the same robust multi-model vote Krisis uses
  used.push("multi-model jury (self-check)");
  const jv: any = await juryConsensus(
    "You verify an AI answer for reliability. Given the QUESTION, the EVIDENCE, and the ANSWER, decide whether the answer is well-supported by the evidence and free of fabrication, then vote exactly one label. GROUNDED = fully supported, no invented facts. PARTLY_GROUNDED = mostly supported but some gaps. WEAK = poorly supported or likely fabricated. UNVERIFIABLE = not enough evidence to judge.",
    `QUESTION: ${q}\n\nEVIDENCE:\n${evidence.slice(0, 2200)}\n\nANSWER: ${answer.slice(0, 700)}`,
    ["GROUNDED", "PARTLY_GROUNDED", "WEAK", "UNVERIFIABLE"]
  ).catch(() => null);
  const jury: AskResult["jury"] = jv && jv.responded >= 2 ? { verdict: jv.label, confidence: jv.confidence, agreement: jv.agreement, models: jv.responded } : null;

  const sources = (web as any[]).map((s) => ({ title: s.title, url: s.url }));
  // Sign a DIGEST of the whole answer, never a prefix of it.
  //
  // This used to sign `answer.slice(0, 700)`. A measured 946-character answer was therefore signed up
  // to character 700 — cut mid-URL — while the buyer was shown all 946. Anyone verifying the receipt
  // against what they received would find they did not match, and the last quarter of every long
  // answer carried no attestation at all. For a service whose entire claim is "you can verify this",
  // that is the worst defect available: a receipt that silently covers less than the deliverable.
  //
  // The digest covers the exact bytes returned, at fixed size, so length can never reintroduce a cap.
  // `answer_excerpt` stays for readability; `answer_sha256` + `answer_chars` are what prove integrity.
  const signed = await signReceipt({
    kind: "ask",
    question: q.slice(0, 300),
    answer_sha256: createHash("sha256").update(answer, "utf8").digest("hex"),
    answer_chars: answer.length,
    answer_excerpt: answer.slice(0, 700),
    jury_verdict: jury?.verdict ?? null,
    observed_at,
  });

  return {
    ok: true, observed_at, question: q, answer, jury,
    powers_used: [...new Set(used)],
    sources, signed,
    disclaimer: "Aletheia answers are grounded and jury-checked, not financial advice.",
  };
}
