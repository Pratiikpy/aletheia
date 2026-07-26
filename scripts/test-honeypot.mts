import { simulateHoneypot } from "../src/sim/honeypot.js";
const t0 = Date.now();
// USDT on Ethereum — has Uniswap V2 liquidity; should be buyable + sellable, not a honeypot.
const r = await simulateHoneypot("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7");
console.log(`\n=== USDT (ethereum) — ${Date.now()-t0}ms ===`);
console.log("simulated:", r.simulated, "hasPair:", r.hasPair, "error:", r.error ?? "-");
console.log("isHoneypot:", r.isHoneypot, "selective:", r.selectiveHoneypot);
console.log("maxBuyTax:", r.maxBuyTax, "maxSellTax:", r.maxSellTax);
for (const v of r.vectors) console.log(" ", v.label, "| bought:", v.boughtOk, "buyTax:", v.buyTax?.toFixed(4), "| sold:", v.soldOk, "sellTax:", v.sellTax?.toFixed(4), v.reason ? "| "+v.reason : "");
