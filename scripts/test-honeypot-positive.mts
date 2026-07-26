import { readFileSync } from "node:fs";
import { parseEther, getContract, encodeDeployData } from "viem";
import { AnvilFork } from "../src/sim/anvil.js";
import { simulateHoneypot } from "../src/sim/honeypot.js";

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";
const ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
const artifact = JSON.parse(readFileSync("out/Honeypot.sol/Honeypot.json", "utf8"));
const abi = artifact.abi;
const bytecode = artifact.bytecode.object as `0x${string}`;

const factoryAbi = [
  { type:"function", name:"createPair", stateMutability:"nonpayable", inputs:[{type:"address"},{type:"address"}], outputs:[{type:"address"}] },
  { type:"function", name:"getPair", stateMutability:"view", inputs:[{type:"address"},{type:"address"}], outputs:[{type:"address"}] },
] as const;
const routerAbi = [
  { type:"function", name:"addLiquidityETH", stateMutability:"payable",
    inputs:[{name:"token",type:"address"},{name:"amountTokenDesired",type:"uint256"},{name:"amountTokenMin",type:"uint256"},{name:"amountETHMin",type:"uint256"},{name:"to",type:"address"},{name:"deadline",type:"uint256"}],
    outputs:[{type:"uint256"},{type:"uint256"},{type:"uint256"}] },
] as const;
const erc20 = [{ type:"function", name:"approve", stateMutability:"nonpayable", inputs:[{type:"address"},{type:"uint256"}], outputs:[{type:"bool"}] },
  { type:"function", name:"setPair", stateMutability:"nonpayable", inputs:[{type:"address"}], outputs:[] }] as const;

const fork = new AnvilFork("ethereum");
await fork.start();
const { client, address: owner } = fork.wallet(0);
const pub = fork.pub;

// 1. deploy honeypot
const deployHash = await client.deployContract({ abi, bytecode, args:[parseEther("1000000")], account: client.account!, chain:null });
const rc = await pub.waitForTransactionReceipt({ hash: deployHash });
const token = rc.contractAddress!;
console.log("deployed honeypot:", token);

// 2. create pair + set it on token
const cpHash = await client.writeContract({ address: FACTORY, abi: factoryAbi, functionName:"createPair", args:[token, WETH], account: client.account!, chain:null });
await pub.waitForTransactionReceipt({ hash: cpHash });
const pair = await pub.readContract({ address: FACTORY, abi: factoryAbi, functionName:"getPair", args:[token, WETH] }) as `0x${string}`;
await pub.waitForTransactionReceipt({ hash: await client.writeContract({ address: token, abi: erc20, functionName:"setPair", args:[pair], account: client.account!, chain:null }) });
console.log("pair:", pair);

// 3. approve router + add liquidity (owner allowed to move tokens to pair)
await pub.waitForTransactionReceipt({ hash: await client.writeContract({ address: token, abi: erc20, functionName:"approve", args:[ROUTER, parseEther("1000000")], account: client.account!, chain:null }) });
const alHash = await client.writeContract({ address: ROUTER, abi: routerAbi, functionName:"addLiquidityETH",
  args:[token, parseEther("500000"), 0n, 0n, owner, 9999999999n], value: parseEther("50"), account: client.account!, chain:null });
await pub.waitForTransactionReceipt({ hash: alHash });
console.log("added liquidity: 500k TRAP / 50 ETH");

// 4. run the sim on THIS fork
const r = await simulateHoneypot("ethereum", token, fork);
console.log("\n=== SIM RESULT ===");
console.log("isHoneypot:", r.isHoneypot, "| hasPair:", r.hasPair);
for (const v of r.vectors) console.log(" ", v.label, "| bought:", v.boughtOk, "| sold:", v.soldOk, v.reason?("| "+v.reason):"");
console.log(r.isHoneypot ? "\n✅ PASS — honeypot correctly detected" : "\n❌ FAIL — honeypot NOT detected");
await fork.stop();
process.exit(r.isHoneypot ? 0 : 1);
