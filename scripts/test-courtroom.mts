import { tokenVerdictCourtroom } from "../src/engine/verdict.js";
const { verdict, ruling } = await tokenVerdictCourtroom("ethereum","0x6982508145454ce325ddbe47a25d4ec3d2311933");
console.log("⚖️  THE VERITY COURTROOM — "+(verdict.subject.symbol??verdict.subject.name));
console.log("\n👨‍⚖️ PROSECUTION:\n"+ruling.prosecution);
console.log("\n🛡️ DEFENSE:\n"+ruling.defense);
console.log("\n⚖️ RULING:\n"+ruling.ruling);
console.log("\n🔨 SENTENCE: "+ruling.sentence);
console.log("\nmodels:", ruling.models);
