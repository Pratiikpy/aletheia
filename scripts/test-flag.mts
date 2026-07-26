import { tokenVerdict } from "../src/engine/verdict.js";
const t0 = Date.now();
const v = await tokenVerdict("bsc", "0x55d398326f99059ff775485246999027b3197955", "flag");
console.log(`flag tier (BSC-USD) — ${Date.now()-t0}ms: ${v.verdict} score=${v.score} conf=${v.confidence} sim=${v.provenance.simulation} signals=${v.signals.length}`);
console.log("summary:", v.summary);
