import { readFileSync } from "node:fs";
import { parseEther } from "viem";
import { AnvilFork } from "../sim/anvil.js";
import { simulateHoneypot } from "../sim/honeypot.js";

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";
const ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";

const factoryAbi = [
  { type: "function", name: "createPair", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "address" }], outputs: [{ type: "address" }] },
  { type: "function", name: "getPair", stateMutability: "view", inputs: [{ type: "address" }, { type: "address" }], outputs: [{ type: "address" }] },
] as const;
const routerAbi = [
  { type: "function", name: "addLiquidityETH", stateMutability: "payable", inputs: [{ name: "token", type: "address" }, { name: "amountTokenDesired", type: "uint256" }, { name: "amountTokenMin", type: "uint256" }, { name: "amountETHMin", type: "uint256" }, { name: "to", type: "address" }, { name: "deadline", type: "uint256" }], outputs: [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }] },
] as const;
const erc20 = [
  { type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "setPair", stateMutability: "nonpayable", inputs: [{ type: "address" }], outputs: [] },
] as const;

/**
 * Deploy a real honeypot contract + Uniswap V2 liquidity on a fork and run the sim against it.
 * Returns whether Aletheia correctly detected the honeypot — a deterministic recall test case.
 */
export async function deployAndDetectHoneypot(): Promise<{ detected: boolean; token: string }> {
  const artifact = JSON.parse(readFileSync("out/Honeypot.sol/Honeypot.json", "utf8"));
  const abi = artifact.abi;
  const bytecode = artifact.bytecode.object as `0x${string}`;

  const fork = new AnvilFork("ethereum");
  await fork.start();
  try {
    const { client, address: owner } = fork.wallet(0);
    const pub = fork.pub;
    const deployHash = await client.deployContract({ abi, bytecode, args: [parseEther("1000000")], account: client.account!, chain: null });
    const rc = await pub.waitForTransactionReceipt({ hash: deployHash });
    const token = rc.contractAddress!;
    await pub.waitForTransactionReceipt({ hash: await client.writeContract({ address: FACTORY, abi: factoryAbi, functionName: "createPair", args: [token, WETH], account: client.account!, chain: null }) });
    const pair = (await pub.readContract({ address: FACTORY, abi: factoryAbi, functionName: "getPair", args: [token, WETH] })) as `0x${string}`;
    await pub.waitForTransactionReceipt({ hash: await client.writeContract({ address: token, abi: erc20, functionName: "setPair", args: [pair], account: client.account!, chain: null }) });
    await pub.waitForTransactionReceipt({ hash: await client.writeContract({ address: token, abi: erc20, functionName: "approve", args: [ROUTER, parseEther("1000000")], account: client.account!, chain: null }) });
    await pub.waitForTransactionReceipt({ hash: await client.writeContract({ address: ROUTER, abi: routerAbi, functionName: "addLiquidityETH", args: [token, parseEther("500000"), 0n, 0n, owner, 9999999999n], value: parseEther("50"), account: client.account!, chain: null }) });
    const r = await simulateHoneypot("ethereum", token, fork);
    return { detected: r.isHoneypot, token };
  } finally {
    await fork.stop();
  }
}
