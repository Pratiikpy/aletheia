import { toFunctionSelector } from "viem";
import { evmClient } from "../adapters/rpc.js";
import type { ChainKey } from "../config.js";

/**
 * Bytecode scam-pattern matcher — a static defense that works even when the source is UNVERIFIED.
 *
 * GoPlus and honeypot checkers largely rely on verified source or dynamic probing. Many rug contracts
 * ship unverified. We scan the raw runtime bytecode for the 4-byte selectors of functions that only
 * exist to trap or fleece holders — owner-only blacklist toggles, trading on/off switches, arbitrary
 * fee setters, max-tx limiters. Presence of a selector is not proof of malice on its own, but a token
 * whose bytecode exposes owner-controlled blacklist + fee + trading-toggle is a textbook rug chassis.
 *
 * Selectors are COMPUTED from signatures (keccak256(sig)[0:4]) via viem — never hardcoded/guessed — so
 * every match is verifiable and reproducible. Keyless; catches the "unverified contract" blind spot.
 */

// Human-readable signatures of trap-shaped functions, grouped by capability. Selectors derived below.
const SIGNATURES: Record<string, string[]> = {
  blacklist: [
    "blacklist(address)",
    "addBlacklist(address)",
    "setBlacklist(address,bool)",
    "removeFromBlacklist(address)",
    "isBlackListed(address)",
    "isBlacklisted(address)",
    "setBots(address[],bool)",
    "setBlacklistBatch(address[],bool)",
  ],
  trading_toggle: [
    "enableTrading()",
    "openTrading()",
    "setTradingEnabled(bool)",
    "removeLimits()",
    "setSwapEnabled(bool)",
    "tradingStatus(bool)",
  ],
  fee_control: [
    "setFee(uint256)",
    "setTaxFee(uint256)",
    "setFees(uint256,uint256)",
    "setSellFee(uint256)",
    "setBuyFee(uint256)",
    "setMaxTxAmount(uint256)",
    "setMaxWalletAmount(uint256)",
  ],
  mint: ["mint(address,uint256)", "mint(uint256)"],
};

export type BytecodeCapability = keyof typeof SIGNATURES;

type Sel = { sel: string; sig: string };
// Compute selectors once at module load — deterministic, verifiable.
const GROUPS: Record<BytecodeCapability, Sel[]> = Object.fromEntries(
  Object.entries(SIGNATURES).map(([cap, sigs]) => [cap, sigs.map((sig) => ({ sel: toFunctionSelector(sig), sig }))])
) as Record<BytecodeCapability, Sel[]>;

export type BytecodeMatch = { capability: BytecodeCapability; selector: string; signature: string };

export type BytecodeScan = {
  ok: boolean;
  observed_at: string;
  isContract: boolean;
  bytecodeSize: number;
  matches: BytecodeMatch[];
  capabilities: BytecodeCapability[]; // distinct capabilities present
  rugChassisScore: number; // 0..1 — how many of {blacklist, fee_control, trading_toggle} co-occur
  error?: string;
};

/** Scan runtime bytecode for embedded 4-byte selectors of trap-shaped functions (pure, testable). */
export function scanBytecode(bytecode: string): { matches: BytecodeMatch[]; capabilities: BytecodeCapability[]; rugChassisScore: number } {
  const hex = (bytecode || "").toLowerCase();
  const matches: BytecodeMatch[] = [];
  for (const [capability, sels] of Object.entries(GROUPS) as [BytecodeCapability, Sel[]][]) {
    for (const { sel, sig } of sels) {
      // a selector appears in the bytecode as a PUSH4 operand inside the function dispatcher
      if (hex.includes(sel.slice(2).toLowerCase())) matches.push({ capability, selector: sel, signature: sig });
    }
  }
  const capabilities = [...new Set(matches.map((m) => m.capability))];
  // "rug chassis": the dangerous combination is owner-controlled blacklist + fee + trading gate together.
  const trapCaps = capabilities.filter((c) => c === "blacklist" || c === "fee_control" || c === "trading_toggle");
  const rugChassisScore = trapCaps.length / 3;
  return { matches, capabilities, rugChassisScore };
}

export async function scanTokenBytecode(chain: ChainKey, address: `0x${string}`): Promise<BytecodeScan> {
  const observed_at = new Date().toISOString();
  try {
    const code = await evmClient(chain).getBytecode({ address }).catch(() => undefined);
    const isContract = !!code && code !== "0x";
    const bytecodeSize = code ? (code.length - 2) / 2 : 0;
    if (!isContract) {
      return { ok: true, observed_at, isContract: false, bytecodeSize: 0, matches: [], capabilities: [], rugChassisScore: 0 };
    }
    const { matches, capabilities, rugChassisScore } = scanBytecode(code!);
    return { ok: true, observed_at, isContract, bytecodeSize, matches, capabilities, rugChassisScore };
  } catch (e: any) {
    return { ok: false, observed_at, isContract: false, bytecodeSize: 0, matches: [], capabilities: [], rugChassisScore: 0, error: e?.message ?? String(e) };
  }
}

/** Exposed for tests/tools: the computed selector table. */
export function selectorTable(): Record<BytecodeCapability, Sel[]> {
  return GROUPS;
}
