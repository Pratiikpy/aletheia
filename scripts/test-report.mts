import { tokenVerdictDeep } from "../src/engine/verdict.js";
const t0 = Date.now();
// PEPE — a real memecoin (not an established stablecoin), good committee test.
const { verdict, report } = await tokenVerdictDeep("ethereum", "0x6982508145454ce325ddbe47a25d4ec3d2311933");
console.log(`\n=== DEEP REPORT (PEPE) — ${Date.now()-t0}ms ===`);
console.log("verdict:", verdict.verdict, verdict.score, "| dims:", Object.keys(verdict.dimensions).join(","));
console.log("\nrecommendation:", report.recommendation, "| conviction:", report.conviction);
console.log("bottom_line:", report.bottom_line);
console.log("strengths:", report.key_strengths);
console.log("risks:", report.key_risks);
console.log("models:", report.debate);
