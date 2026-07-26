import { tokenVerdict } from "../src/engine/verdict.js";
for (const [chain, addr, label] of [
  ["ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT"],
] as const) {
  const t0 = Date.now();
  const v = await tokenVerdict(chain, addr, "full");
  console.log(`\n=== ${label} full — ${Date.now()-t0}ms ===`);
  console.log("verdict:", v.verdict, "score:", v.score, "confidence:", v.confidence);
  console.log("dimensions:", Object.entries(v.dimensions).map(([k,d]:any)=>`${k}:${d.verdict}/${d.score}`).join("  "));
  console.log("summary:", v.summary);
  console.log("market signals:", v.signals.filter(s=>s.dimension==='market_structure').map(s=>s.code).join(", ") || "(none)");
}
