import { chainTip, erc20Meta } from "../src/adapters/rpc.js";
const tip = await chainTip("ethereum");
console.log("ETH tip:", tip.blockNumber.toString(), "chainId", tip.chainId);
const usdt = await erc20Meta("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7");
console.log("USDT meta:", { name: usdt.name, symbol: usdt.symbol, decimals: usdt.decimals, isContract: usdt.isContract, bytecodeSize: usdt.bytecodeSize });
