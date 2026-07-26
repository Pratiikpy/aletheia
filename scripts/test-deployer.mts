import { gather } from "../src/engine/context.js";
import { tokenVerdict } from "../src/engine/verdict.js";
const ctx = await gather("ethereum","0x6982508145454ce325ddbe47a25d4ec3d2311933",{sim:false});
console.log("PEPE deployer:", { creator: ctx.deployer?.creator?.slice(0,10), txCount: ctx.deployer?.txCount, funder: ctx.deployer?.funder?.slice(0,10), mixer: ctx.deployer?.funderIsMixer, established: ctx.established });
const v = await tokenVerdict("ethereum","0xdac17f958d2ee523a2206206994597c13d831ec7","flag");
console.log("USDT verdict (must stay GO/clean):", v.verdict, v.score, "deployer signals:", v.signals.filter(s=>s.code.includes("deployer")||s.code.includes("rugger")).map(s=>s.code));
