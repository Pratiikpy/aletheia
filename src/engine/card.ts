import type { Verdict } from "../types/verdict.js";

const EMOJI: Record<Verdict["verdict"], string> = { GO: "🟢", CAUTION: "🟡", AVOID: "🔴" };
const bar = (score: number) => { const f = Math.round(score / 10); return "█".repeat(f) + "░".repeat(10 - f); };

/** Shareable markdown card — the human-facing / X-postable "verdict card" (a rug autopsy when AVOID). */
export function verdictCardMarkdown(v: Verdict): string {
  const s = v.subject;
  const top = [...v.signals].sort((a, b) => b.severity - a.severity).slice(0, 4);
  const lines: string[] = [];
  lines.push(`## ${EMOJI[v.verdict]} ${v.verdict} — ${s.name ?? s.symbol ?? short(s.address)}  ·  ${v.score}/100`);
  lines.push(`\`${bar(v.score)}\`  confidence ${(v.confidence * 100).toFixed(0)}%  ·  ${s.chain}`);
  lines.push("");
  lines.push(`> ${v.summary}`);
  lines.push("");
  if (top.length) {
    lines.push(v.verdict === "AVOID" ? "**Why it's dangerous:**" : "**Key findings:**");
    for (const sig of top) lines.push(`- ${sevDot(sig.severity)} ${sig.finding}${sig.evidence[0]?.snippet ? `  \`${sig.evidence[0].snippet}\`` : ""}`);
    lines.push("");
  }
  const dims = Object.entries(v.dimensions).map(([k, d]) => `${k.replace(/_/g, " ")} ${EMOJI[d!.verdict]}`).join(" · ");
  if (dims) lines.push(`_dimensions:_ ${dims}`);
  lines.push(`_${countEvidence(v)} pieces of on-chain evidence · verified by Aletheia_`);
  return lines.join("\n");
}

/** ≤280-char X-postable one-liner. */
export function verdictCardTweet(v: Verdict): string {
  const s = v.subject;
  const name = s.symbol ?? s.name ?? short(s.address);
  const lead = v.verdict === "AVOID" ? "🔴 AVOID" : v.verdict === "CAUTION" ? "🟡 CAUTION" : "🟢 GO";
  const why = [...v.signals].sort((a, b) => b.severity - a.severity)[0]?.finding ?? v.summary;
  let t = `${lead} ${name} (${s.chain}) — ${v.score}/100, ${(v.confidence * 100).toFixed(0)}% conf.\n${why}\n— verified on-chain by Aletheia. #OKXAI`;
  if (t.length > 280) t = t.slice(0, 277) + "…";
  return t;
}

function sevDot(sev: number) { return sev >= 5 ? "🔴" : sev >= 3 ? "🟠" : sev >= 2 ? "🟡" : "⚪"; }
function short(a: string) { return a.slice(0, 6) + "…" + a.slice(-4); }
function countEvidence(v: Verdict) { return v.signals.reduce((n, s) => n + s.evidence.length, 0); }
