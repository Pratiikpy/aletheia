import { spawn, type ChildProcess } from "node:child_process";
import { createPublicClient, createWalletClient, http, type PublicClient, type WalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { alchemyRpc, type ChainKey } from "../config.js";

/** anvil's deterministic funded dev accounts (10000 native each). */
export const ANVIL_ACCOUNTS = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
] as const;

let portCounter = 8600;

export class AnvilFork {
  private proc: ChildProcess | null = null;
  public rpcUrl: string;
  public pub!: PublicClient;
  public forkBlockNumber: bigint | null = null; // the exact block this fork pinned — reproducibility anchor
  private port: number;

  constructor(private chain: ChainKey, private forkBlock?: bigint) {
    this.port = portCounter++;
    this.rpcUrl = `http://127.0.0.1:${this.port}`;
  }

  async start(timeoutMs = 30000): Promise<void> {
    const forkUrl = alchemyRpc(this.chain);
    const args = ["--fork-url", forkUrl, "--port", String(this.port), "--silent", "--no-rate-limit"];
    if (this.forkBlock) args.push("--fork-block-number", String(this.forkBlock));
    this.proc = spawn("anvil", args, { stdio: "ignore", shell: process.platform === "win32" });
    this.proc.on("error", (e) => console.error("anvil spawn error:", e.message));

    this.pub = createPublicClient({ transport: http(this.rpcUrl, { retryCount: 0 }) }) as PublicClient;

    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        this.forkBlockNumber = await this.pub.getBlockNumber(); // the pinned fork block (reproducibility anchor)
        return; // ready
      } catch {
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    await this.stop();
    throw new Error(`anvil fork for ${this.chain} did not start within ${timeoutMs}ms`);
  }

  wallet(pkIndex = 0): { client: WalletClient; address: `0x${string}` } {
    const pk = ANVIL_ACCOUNTS[pkIndex % ANVIL_ACCOUNTS.length]!;
    const account = privateKeyToAccount(pk as `0x${string}`);
    const client = createWalletClient({ account, transport: http(this.rpcUrl, { retryCount: 0 }) });
    return { client, address: account.address };
  }

  /** A brand-new random EOA, funded with native — to defeat tx.origin/whitelist anti-sim. */
  async freshWallet(nativeWei: bigint): Promise<{ client: WalletClient; address: `0x${string}` }> {
    const pk = ("0x" + Array.from({ length: 64 }, () => "0123456789abcdef"[Math.floor(seededRand() * 16)]).join("")) as `0x${string}`;
    const account = privateKeyToAccount(pk);
    await this.rpc("anvil_setBalance", [account.address, "0x" + nativeWei.toString(16)]);
    const client = createWalletClient({ account, transport: http(this.rpcUrl, { retryCount: 0 }) });
    return { client, address: account.address };
  }

  async setBalance(addr: `0x${string}`, wei: bigint): Promise<void> {
    await this.rpc("anvil_setBalance", [addr, "0x" + wei.toString(16)]);
  }
  async mine(blocks = 1): Promise<void> {
    await this.rpc("anvil_mine", ["0x" + blocks.toString(16)]);
  }
  async snapshot(): Promise<string> {
    return await this.rpc("evm_snapshot", []);
  }
  async revert(id: string): Promise<void> {
    await this.rpc("evm_revert", [id]);
  }
  async setNextTimestamp(ts: number): Promise<void> {
    await this.rpc("evm_setNextBlockTimestamp", [ts]);
  }

  async rpc(method: string, params: any[]): Promise<any> {
    const res = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(30_000),
    });
    const j: any = await res.json();
    return j.result;
  }

  async stop(): Promise<void> {
    if (this.proc && !this.proc.killed) {
      this.proc.kill("SIGKILL");
      this.proc = null;
    }
  }
}

// Deterministic-ish PRNG seeded from a counter (Math.random is unavailable in some sandboxes;
// randomness only needs to vary the throwaway EOA, not be cryptographic).
let _seed = 0x9e3779b9 ^ 0x2545f491;
function seededRand(): number {
  _seed ^= _seed << 13;
  _seed ^= _seed >>> 17;
  _seed ^= _seed << 5;
  return ((_seed >>> 0) % 1_000_000) / 1_000_000;
}
