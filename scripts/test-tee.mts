import { tokenVerdict } from "../src/engine/verdict.js";
const v = await tokenVerdict("ethereum","0x6982508145454ce325ddbe47a25d4ec3d2311933","full");
console.log("verdict:", v.verdict, v.score);
console.log("summary:", v.summary);
console.log("ai_attestation:", v.ai_attestation);
