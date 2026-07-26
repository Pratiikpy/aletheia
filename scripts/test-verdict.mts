import { tokenVerdict } from "../src/engine/verdict.js";
const t0 = Date.now();
const v = await tokenVerdict("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7", "full");
console.log(`\n=== VERDICT (USDT, full) — ${Date.now()-t0}ms ===`);
console.log(JSON.stringify({
  subject: v.subject, verdict: v.verdict, score: v.score, confidence: v.confidence,
  summary: v.summary, dimensions: v.dimensions,
  signals: v.signals.map(s=>({code:s.code,sev:s.severity,hard:s.is_hard_flag,ev:s.evidence.length})),
  provenance: v.provenance, cost: v.cost, latency_ms: v.latency_ms,
}, null, 2));
