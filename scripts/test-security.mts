import { scoreSecurity } from "../src/engine/dimensions/security.js";
for (const [chain, addr, label] of [
  ["ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT (clean, but slippage_modifiable=1)"],
] as const) {
  const t0 = Date.now();
  const r = await scoreSecurity(chain, addr);
  console.log(`\n=== ${label} — ${Date.now()-t0}ms ===`);
  console.log("verdict:", r.verdict, "score:", r.score, "confidence:", r.confidence);
  console.log("summary:", r.summary);
  for (const s of r.signals) console.log(`  [${s.severity}] ${s.code}${s.is_hard_flag?" (HARD)":""} — ${s.finding}\n      evidence: ${s.evidence.map(e=>e.source+":"+(e.snippet||e.detail)).join(" | ")}`);
}
