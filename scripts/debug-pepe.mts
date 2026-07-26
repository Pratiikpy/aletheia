import { simulateHoneypot } from "../src/sim/honeypot.js";
for (let i=0;i<2;i++){
  const r = await simulateHoneypot("ethereum", "0x6982508145454ce325ddbe47a25d4ec3d2311933");
  console.log(`run${i}: isHoneypot=${r.isHoneypot} selective=${r.selectiveHoneypot} maxSellTax=${r.maxSellTax}`);
  for (const v of r.vectors) console.log("  ", v.label, "bought:", v.boughtOk, "sold:", v.soldOk, v.reason?("| "+v.reason.slice(0,80)):"");
}
