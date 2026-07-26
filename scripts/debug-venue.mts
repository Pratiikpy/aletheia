import { simulateHoneypot } from "../src/sim/honeypot.js";
for (const [c,a,l] of [["ethereum","0x6982508145454ce325ddbe47a25d4ec3d2311933","PEPE"],["ethereum","0xdac17f958d2ee523a2206206994597c13d831ec7","USDT"]] as const){
  const r = await simulateHoneypot(c,a as `0x${string}`);
  console.log(`${l}: honeypot=${r.isHoneypot} selective=${r.selectiveHoneypot} hasPair=${r.hasPair} | ${r.vectors.map(v=>`${v.boughtOk?'B':'-'}${v.soldOk?'S':'-'}`).join(' ')} | ${r.vectors[0]?.reason??''}`);
}
