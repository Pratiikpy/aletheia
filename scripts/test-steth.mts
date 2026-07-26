import { tokenVerdict } from "../src/engine/verdict.js";
// stETH — genuinely clean but honeypot.is FALSE-POSITIVES it (rebasing). Verity must NOT flag it AVOID.
const v = await tokenVerdict("ethereum","0xae7ab96520de3a18e5e111b5eaab095312d7fe84","full");
console.log("stETH verdict:", v.verdict, "score:", v.score, "conf:", v.confidence);
console.log("hard flags:", v.signals.filter(s=>s.is_hard_flag).map(s=>s.code));
console.log("summary:", v.summary);
console.log(v.verdict==="AVOID" ? "❌ FALSE POSITIVE (bad)" : "✅ correctly NOT flagged as honeypot");
