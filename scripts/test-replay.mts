import { simulateHoneypot, replaySim } from "../src/sim/honeypot.js";
const TOK = "0x6982508145454ce325ddbe47a25d4ec3d2311933"; // PEPE
const r1 = await simulateHoneypot("ethereum", TOK);
console.log("original:", { isHoneypot: r1.isHoneypot, venue: r1.proof?.venue, forkBlock: r1.proof?.forkBlock });
console.log("proof.replay:", r1.proof?.replay);
if (r1.proof) {
  const r2 = await replaySim("ethereum", TOK, r1.proof.forkBlock);
  const match = r2.isHoneypot === r1.isHoneypot && r2.selectiveHoneypot === r1.selectiveHoneypot;
  console.log("replay @block", r1.proof.forkBlock, "->", { isHoneypot: r2.isHoneypot }, match ? "✅ REPRODUCIBLE (identical)" : "❌ mismatch");
}
