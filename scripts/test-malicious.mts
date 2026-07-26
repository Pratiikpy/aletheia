import { gather } from "../src/engine/context.js";
const ctx = await gather("ethereum","0xdac17f958d2ee523a2206206994597c13d831ec7",{sim:false});
console.log("USDT deployer:", { creator: ctx.deployer?.creator?.slice(0,10), flags: ctx.deployer?.maliciousFlags, maliciousContracts: ctx.deployer?.maliciousContractsCreated });
