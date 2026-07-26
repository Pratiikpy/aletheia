import "dotenv/config";
import { createWalletClient, createPublicClient, http, defineChain, keccak256, toHex, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Verdict } from "../types/verdict.js";

/**
 * On-chain proof-of-correctness ledger on X Layer. Each verdict is committed BEFORE the outcome is
 * known (immutable, timestamped), then graded later — a publicly auditable accuracy record.
 * The creative headline: Aletheia stakes its reputation on-chain. Trust becomes "audit me," not "trust me".
 */

export const xlayerTestnet = defineChain({
  id: 1952, name: "X Layer Testnet", nativeCurrency: { name: "OKB", symbol: "OKB", decimals: 18 },
  rpcUrls: { default: { http: [process.env.XLAYER_TESTNET_RPC ?? "https://testrpc.xlayer.tech"] } },
});

const REGISTRY = (process.env.VERITY_REGISTRY_ADDRESS ?? "") as `0x${string}`;
const RULING_REGISTRY = (process.env.RULING_REGISTRY_ADDRESS ?? "") as `0x${string}`;
const RULING_ABI = [
  { type: "function", name: "sealRuling", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }, { type: "uint8" }, { type: "uint8" }, { type: "uint16" }, { type: "uint16" }], outputs: [] },
  { type: "function", name: "total", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
] as const;
const ABI = [
  { type: "function", name: "commit", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }, { type: "uint8" }, { type: "uint8" }, { type: "uint8" }], outputs: [] },
  { type: "function", name: "grade", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "bool" }], outputs: [] },
  { type: "function", name: "total", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "graded", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "correct", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "accuracyBps", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
] as const;

const VERDICT_NUM: Record<Verdict["verdict"], number> = { GO: 0, CAUTION: 1, AVOID: 2 };

export function isAttestConfigured(): boolean {
  return !!(REGISTRY && process.env.EVM_WALLET_PRIVATE_KEY);
}

function clients() {
  const account = privateKeyToAccount(process.env.EVM_WALLET_PRIVATE_KEY as `0x${string}`);
  return {
    account,
    wallet: createWalletClient({ account, chain: xlayerTestnet, transport: http() }),
    pub: createPublicClient({ chain: xlayerTestnet, transport: http() }),
  };
}

/** Deterministic commitment id for a verdict (the thing anchored on-chain). */
export function verdictId(v: Verdict): Hex {
  return keccak256(toHex(`${v.subject.chain}:${v.subject.address}:${v.verdict}:${v.score}:${v.generated_at}`));
}

/** Commit a verdict on-chain (X Layer). Returns the id + tx hash. */
export async function attestVerdict(v: Verdict): Promise<{ id: Hex; txHash: Hex } | null> {
  if (!isAttestConfigured()) return null;
  const { account, wallet, pub } = clients();
  const id = verdictId(v);
  const subject = /^0x[a-fA-F0-9]{40}$/.test(v.subject.address) ? (v.subject.address as `0x${string}`) : ("0x0000000000000000000000000000000000000000" as const);
  const txHash = await wallet.writeContract({
    address: REGISTRY, abi: ABI, functionName: "commit",
    args: [id, subject, VERDICT_NUM[v.verdict], Math.round(v.score), Math.round(v.confidence * 100)],
    account, chain: xlayerTestnet,
  });
  await pub.waitForTransactionReceipt({ hash: txHash });
  return { id, txHash };
}

/** Seal a Settle It ruling on-chain as a STRUCTURED, decodable attestation (X Layer): keyed by the
 *  record's sha256 seal, storing winner/confidence/agreement + evidence & judge counts, so anyone
 *  can look the ruling up and verify it against the cited transcript. Null if unconfigured. */
export async function attestSeal(
  sealHex: string, question: string, code: number, confidence: number, agreement: number, sources: number, judges: number,
): Promise<{ id: Hex; txHash: Hex; registry: string } | null> {
  if (!RULING_REGISTRY || !process.env.EVM_WALLET_PRIVATE_KEY) return null;
  const seal = (/^0x[a-fA-F0-9]{64}$/.test(sealHex) ? sealHex : `0x${"0".repeat(64)}`) as Hex;
  const questionHash = keccak256(toHex(String(question).slice(0, 600)));
  const u8 = (v: number, max: number) => Math.min(max, Math.max(0, Math.round(v)));
  const u16 = (v: number) => Math.min(65535, Math.max(0, Math.round(v)));
  const { account, wallet, pub } = clients();
  const txHash = await wallet.writeContract({
    address: RULING_REGISTRY, abi: RULING_ABI, functionName: "sealRuling",
    args: [seal, questionHash, u8(code, 3), u8(confidence, 100), u8(agreement, 100), u16(sources), u16(judges)],
    account, chain: xlayerTestnet,
  });
  await pub.waitForTransactionReceipt({ hash: txHash });
  return { id: seal, txHash, registry: RULING_REGISTRY };
}

/** Grade a prior commitment once the outcome is known. */
export async function gradeVerdict(id: Hex, wasCorrect: boolean): Promise<Hex | null> {
  if (!isAttestConfigured()) return null;
  const { account, wallet, pub } = clients();
  const txHash = await wallet.writeContract({ address: REGISTRY, abi: ABI, functionName: "grade", args: [id, wasCorrect], account, chain: xlayerTestnet });
  await pub.waitForTransactionReceipt({ hash: txHash });
  return txHash;
}

/** Public, on-chain accuracy record. */
export async function getRegistryStats(): Promise<{ total: number; graded: number; correct: number; accuracyPct: number; registry: string } | null> {
  if (!REGISTRY) return null;
  const { pub } = clients();
  const [total, graded, correct, bps] = await Promise.all([
    pub.readContract({ address: REGISTRY, abi: ABI, functionName: "total" }),
    pub.readContract({ address: REGISTRY, abi: ABI, functionName: "graded" }),
    pub.readContract({ address: REGISTRY, abi: ABI, functionName: "correct" }),
    pub.readContract({ address: REGISTRY, abi: ABI, functionName: "accuracyBps" }),
  ]);
  return { total: Number(total), graded: Number(graded), correct: Number(correct), accuracyPct: Number(bps) / 100, registry: REGISTRY };
}
