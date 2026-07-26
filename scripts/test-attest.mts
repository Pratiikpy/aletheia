import { tokenVerdict } from "../src/engine/verdict.js";
import { attestVerdict, gradeVerdict, getRegistryStats, verdictId } from "../src/attest/registry.js";
console.log("stats before:", await getRegistryStats());
const v = await tokenVerdict("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7", "flag");
console.log(`\nverdict: ${v.verdict}/${v.score} → committing on X Layer...`);
const a = await attestVerdict(v);
console.log("committed on-chain:", a?.txHash);
console.log("verdict id:", a?.id);
console.log("\nstats after commit:", await getRegistryStats());
// grade it (USDT did not rug → an AVOID would be wrong, a GO/CAUTION correct)
if (a) { await gradeVerdict(a.id, true); console.log("graded correct."); }
console.log("stats after grade:", await getRegistryStats());
