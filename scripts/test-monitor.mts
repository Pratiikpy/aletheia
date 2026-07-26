import { diffSnapshots, type Snapshot } from "../src/monitor/watch.js";
const base: Snapshot = { chain:"ethereum", address:"0xabc", verdict:"GO", score:90, liquidityUsd:1_000_000, hardCodes:[], sevCodes:{healthy_market:1}, at:new Date().toISOString() };
// scenario 1: honeypot flip + verdict downgrade + liquidity pull
const worse: Snapshot = { ...base, verdict:"AVOID", score:12, liquidityUsd:200_000, hardCodes:["selective_honeypot"], sevCodes:{selective_honeypot:5}, at:new Date().toISOString() };
console.log("=== scenario: token turned malicious ===");
for (const a of diffSnapshots(base, worse)) console.log(`[${a.severity}/5] ${a.title}\n   ${a.brief}\n   → ${a.action}\n`);
// scenario 2: no material change
console.log("=== scenario: no change ===");
const same = { ...base, at:new Date().toISOString() };
console.log("alerts:", diffSnapshots(base, same).length);
