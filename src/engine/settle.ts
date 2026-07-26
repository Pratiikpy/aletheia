import { createHash } from "node:crypto";
import { chat, JURY_MODELS } from "../ai/router.js";
import { gatherEvidence, evidenceBlock, type Source } from "../evidence/websearch.js";
import { attestSeal } from "../attest/registry.js";
import { signReceipt, type SignedReceipt } from "../attest/sign.js";

/**
 * Settle It v2 — the evidence court that shows its work.
 *
 * How it beats an opaque "diverse-LLM validator vote": the ruling is
 *   - GROUNDED: real web sources retrieved at decision time (keyless: DDG via Jina), cited [n];
 *   - DEBATED: two advocate models argue each side over an opening + a rebuttal round, not one vote;
 *   - JUDGED: a diverse multi-model panel scores who the *evidence and logic* favor, not who argued louder;
 *   - TRANSPARENT: the full evidence list + every debate turn + every judge's vote are returned;
 *   - SEALED: a sha256 of the whole record is committed on-chain (X Layer), so the ruling is
 *     tamper-evident and publicly referenceable forever.
 * GenLayer gives you a vote; Aletheia gives you a receipt you can open and check.
 */

export type DebateTurn = { speaker: "A" | "B"; phase: "opening" | "rebuttal"; model: string; text: string };
export type JudgeVote = { model: string; winner: "A" | "B" | "TIE" | "UNRESOLVED"; score_a: number; score_b: number; confidence: number; decisive: string };
export type SettleResult = {
  ok: boolean;
  observed_at: string;
  question: string;
  positions: { a: string; b: string };
  ruling: string;
  winner: "A" | "B" | "tie" | "unresolved";
  confidence: number;
  the_final_word: string;
  scores: { a: number; b: number };
  citations: { id: number; title: string; url: string }[];
  transcript: DebateTurn[];
  jury: { agreement: number; responded: number; votes: JudgeVote[] };
  evidence_count: number;
  seal: string;
  signed: SignedReceipt | null;
  attestation: { id: string; txHash: string; chain: string; registry: string } | null;
  disclaimer: string;
};

const WINNER_LABELS = ["A", "B", "TIE", "UNRESOLVED"] as const;

function parseJson(s: string): any | undefined {
  const t = s.trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
  try { return JSON.parse(t); } catch { /* find embedded */ }
  const start = t.indexOf("{"); if (start < 0) return undefined;
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < t.length; i++) {
    const c = t[i]!;
    if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true; else if (c === "{") depth++; else if (c === "}") { if (--depth === 0) { try { return JSON.parse(t.slice(start, i + 1)); } catch { return undefined; } } }
  }
  return undefined;
}
const clamp01 = (n: any) => Math.max(0, Math.min(1, Number(n) || 0));
const clamp100 = (n: any) => Math.max(0, Math.min(100, Math.round(Number(n) || 0)));

/** When the caller gives only a question, derive the two strongest opposing positions to debate. */
async function framePositions(question: string): Promise<{ a: string; b: string }> {
  try {
    const { content } = await chat(
      [
        { role: "system", content: 'Given a disputed question, state the two strongest OPPOSING positions a reasoned person could hold. Return ONLY JSON {"a":"...","b":"..."}, each <=18 words.' },
        { role: "user", content: question },
      ],
      { tier: "strong", maxTokens: 200, temperature: 0.2 },
    );
    const j = parseJson(content);
    if (j?.a && j?.b) return { a: String(j.a).slice(0, 200), b: String(j.b).slice(0, 200) };
  } catch { /* fall through */ }
  return { a: "The claim is true / should be affirmed.", b: "The claim is false / should be rejected." };
}

/** Strip any leaked task/role/meta reasoning a model prepends before its actual argument. */
function cleanAdvocate(s: string): string {
  let t = s.trim().replace(/^["'`]+|["'`]+$/g, "").trim();
  const meta = /^(the user\b|as advocate\b|okay[,.]?|alright[,.]?|sure[,.]?|first,?\s+i\b|i (need|should|must|will|'?ll|have to)\b|let me\b|let's\b|wait[,.]?|hmm[,.]?|so,?\s+i\b|my (task|job|role|goal|position)\b|re-?read|i'?m (asked|being asked|supposed)|the (task|prompt|instruction)\b)/i;
  const parts = t.split(/(?<=[.!?])\s+/);
  while (parts.length > 1 && meta.test(parts[0]!.trim())) parts.shift();
  t = parts.join(" ").trim();
  return t || s.trim();
}

async function advocate(model: string, side: "A" | "B", position: string, question: string, evidence: string, phase: "opening" | "rebuttal", opponentText?: string): Promise<DebateTurn> {
  const rules = `Write ONLY the argument itself, first-person. Do NOT mention "the user", "advocate", your role/task, or your reasoning process; no preamble or meta-commentary — start directly with the substance. Cite the numbered evidence as [n].`;
  const sys = phase === "opening"
    ? `You argue that this position is correct: "${position}". Be persuasive but HONEST — if a source undercuts your side, concede it rather than distort it. ${rules} Under 140 words.`
    : `You argue for: "${position}". Rebut the opponent's specific claims below — name their weakest point, an unsupported claim, or a misread source, and counter it with evidence. Do not repeat your opening; do not concede the whole case. ${rules} Under 110 words.`;
  const user = `DISPUTE: ${question}\n\nEVIDENCE:\n${evidence}${opponentText ? `\n\nOPPONENT'S ARGUMENT (rebut this):\n${opponentText}` : ""}`;
  try {
    const { content } = await chat([{ role: "system", content: sys }, { role: "user", content: user }], { model, maxTokens: 520, temperature: 0.3 });
    const text = cleanAdvocate(content).slice(0, 1400);
    return { speaker: side, phase, model, text: text.length >= 15 ? text : (phase === "rebuttal" ? "Concedes — no substantive rebuttal to the opponent's evidence." : "(no argument produced)") };
  } catch { return { speaker: side, phase, model, text: "(no argument produced)" }; }
}

async function judge(model: string, question: string, pos: { a: string; b: string }, evidence: string, debate: string): Promise<JudgeVote | null> {
  const sys = `You are an impartial judge. Read the dispute, the evidence, and both advocates' arguments + rebuttals. Decide who the EVIDENCE AND LOGIC favor — NOT who argued more forcefully. Score each side 0-100 on how well the evidence supports it. Choose UNRESOLVED only if the evidence is genuinely insufficient. Return ONLY JSON {"winner":"A"|"B"|"TIE"|"UNRESOLVED","score_a":0-100,"score_b":0-100,"confidence":0.0-1.0,"decisive":"<=25 words, cite [n]"}.`;
  const user = `DISPUTE: ${question}\nPosition A: ${pos.a}\nPosition B: ${pos.b}\n\nEVIDENCE:\n${evidence}\n\nDEBATE:\n${debate}`;
  try {
    const { content } = await chat([{ role: "system", content: sys }, { role: "user", content: user }], { model, maxTokens: 700, temperature: 0.2 });
    const j = parseJson(content);
    if (!j || !WINNER_LABELS.includes(j.winner)) return null;
    return { model, winner: j.winner, score_a: clamp100(j.score_a), score_b: clamp100(j.score_b), confidence: clamp01(j.confidence), decisive: String(j.decisive ?? "").slice(0, 160) };
  } catch { return null; }
}

export async function settleDispute(question: string, sideA?: string, sideB?: string): Promise<SettleResult> {
  const observed_at = new Date().toISOString();
  const q = String(question || "").slice(0, 600).trim();

  // positions: use the caller's two sides, else derive the strongest opposing positions
  const positions = sideA && sideB ? { a: String(sideA).slice(0, 300), b: String(sideB).slice(0, 300) } : await framePositions(q);

  // 1) gather real evidence
  const sources: Source[] = await gatherEvidence(q, positions.a, positions.b, { maxSources: 5, deepRead: 2 });
  const evidence = evidenceBlock(sources);

  // 2) debate — openings (parallel), then rebuttals (parallel) using two distinct advocate models
  const [mA, mB] = [JURY_MODELS[0]!, JURY_MODELS[1]!];
  const [openA, openB] = await Promise.all([
    advocate(mA, "A", positions.a, q, evidence, "opening"),
    advocate(mB, "B", positions.b, q, evidence, "opening"),
  ]);
  const [rebA, rebB] = await Promise.all([
    advocate(mA, "A", positions.a, q, evidence, "rebuttal", openB.text),
    advocate(mB, "B", positions.b, q, evidence, "rebuttal", openA.text),
  ]);
  const transcript: DebateTurn[] = [openA, openB, rebA, rebB];
  const debateText = transcript.map((t) => `[${t.speaker} ${t.phase}] ${t.text}`).join("\n\n");

  // 3) judge panel — diverse models score who the evidence favors
  const settled = await Promise.all(JURY_MODELS.map((m) => judge(m, q, positions, evidence, debateText)));
  const votes = settled.filter((v): v is JudgeVote => v !== null);

  // 4) aggregate
  let winnerLabel: JudgeVote["winner"] = "UNRESOLVED", agreement = 0, confidence = 0;
  let scoreA = 0, scoreB = 0;
  if (votes.length) {
    const tally = new Map<string, JudgeVote[]>();
    for (const v of votes) (tally.get(v.winner) ?? tally.set(v.winner, []).get(v.winner)!).push(v);
    const [label, group] = [...tally.entries()].sort((a, b) => b[1].length - a[1].length)[0]!;
    winnerLabel = label as JudgeVote["winner"];
    agreement = group.length / votes.length;
    confidence = Number((group.reduce((s, v) => s + v.confidence, 0) / group.length * agreement).toFixed(2));
    scoreA = Math.round(votes.reduce((s, v) => s + v.score_a, 0) / votes.length);
    scoreB = Math.round(votes.reduce((s, v) => s + v.score_b, 0) / votes.length);
  }
  const winner: SettleResult["winner"] = winnerLabel === "A" ? "A" : winnerLabel === "B" ? "B" : winnerLabel === "TIE" ? "tie" : "unresolved";
  const ruling = winner === "A" ? "A prevails" : winner === "B" ? "B prevails" : winner === "tie" ? "Both partly right" : "Unresolved on the evidence";

  // 5) final word — plain-English, cited
  const decisive = votes.filter((v) => v.winner === winnerLabel).map((v) => v.decisive).filter(Boolean);
  let finalWord = "";
  try {
    const { content } = await chat(
      [
        { role: "system", content: "You are the judge delivering the final ruling in 2-3 plain, authoritative sentences. State who is right and the single decisive, evidence-based reason. Cite a source as [n] if one settles it. Do not hedge beyond what the evidence supports." },
        { role: "user", content: `DISPUTE: ${q}\nPosition A: ${positions.a}\nPosition B: ${positions.b}\n\nEVIDENCE:\n${evidence}\n\nRuling: ${ruling} (${Math.round(agreement * 100)}% of judges agree). Deciding points: ${decisive.join("; ") || "(limited)"}` },
      ],
      { tier: "strong", maxTokens: 340, temperature: 0.3 },
    );
    finalWord = content.trim();
  } catch { finalWord = decisive[0] || "The panel could not reach a confident ruling on the available evidence."; }

  // 6) seal the whole record + commit on-chain (tamper-evident, publicly verifiable)
  const record = { observed_at, question: q, positions, winner, confidence, scores: { a: scoreA, b: scoreB }, sources: sources.map((s) => ({ id: s.id, url: s.url })), transcript: transcript.map((t) => ({ s: t.speaker, p: t.phase, t: t.text })), votes };
  const seal = createHash("sha256").update(JSON.stringify(record)).digest("hex");
  // sign the ruling → a receipt anyone can recover the signer from and re-check offline
  const signed = await signReceipt({ kind: "settle_it", question: q, winner, confidence, score_a: scoreA, score_b: scoreB, sources: sources.map((s) => s.url), seal, observed_at });
  let attestation: SettleResult["attestation"] = null;
  try {
    const winCode = winner === "A" ? 0 : winner === "B" ? 1 : winner === "tie" ? 2 : 3;
    const att = await attestSeal(`0x${seal}`, q, winCode, Math.round(confidence * 100), Math.round(agreement * 100), sources.length, votes.length);
    if (att) attestation = { id: att.id, txHash: att.txHash, chain: "X Layer Testnet", registry: att.registry };
  } catch { attestation = null; }

  return {
    ok: true, observed_at, question: q, positions,
    ruling, winner, confidence, the_final_word: finalWord,
    scores: { a: scoreA, b: scoreB },
    citations: sources.map((s) => ({ id: s.id, title: s.title, url: s.url })),
    transcript,
    jury: { agreement: Number(agreement.toFixed(2)), responded: votes.length, votes },
    evidence_count: sources.length,
    seal,
    signed,
    attestation,
    disclaimer: "Aletheia's ruling is an evidence-and-reason judgment by a diverse model panel over cited sources, not legal advice.",
  };
}
