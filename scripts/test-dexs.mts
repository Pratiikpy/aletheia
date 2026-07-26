import { getMarket } from "../src/adapters/dexscreener.js";
for (const [chain, addr, label] of [
  ["ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT (quote asset)"],
  ["ethereum", "0x6982508145454ce325 ddbe47a25d4ec3d2311933".replace(/\s/g,''), "PEPE (base token)"],
] as const) {
  const m = await getMarket(chain, addr);
  console.log(`${label}: ok=${m.ok} pairs=${m.pairs.length} totalLiq=$${Math.round(m.totalLiquidityUsd).toLocaleString()} err=${m.error??'-'}`);
  if (m.topPair) console.log(`   top: ${m.topPair.dexId} liq=$${Math.round(m.topPair.liquidityUsd).toLocaleString()} vol24=$${Math.round(m.topPair.volumeH24).toLocaleString()} buys/sells=${m.topPair.txnsH24Buys}/${m.topPair.txnsH24Sells}`);
}
// raw check for USDT
const res = await fetch("https://api.dexscreener.com/latest/dex/tokens/0xdac17f958d2ee523a2206206994597c13d831ec7");
const j:any = await res.json();
console.log("RAW usdt pairs count:", j?.pairs?.length, "first chainId:", j?.pairs?.[0]?.chainId, "first liq:", j?.pairs?.[0]?.liquidity?.usd);
