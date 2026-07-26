import { parseEther, maxUint256, type WalletClient } from "viem";
import type { ChainKey } from "../config.js";
import { AnvilFork } from "./anvil.js";
import { DEX, ROUTER_ABI, ERC20_ABI, DEX_V3, V3_FEES, V3_FACTORY_ABI, V3_POOL_ABI, V3_ROUTER_ABI } from "./dex.js";

type Venue =
  | { kind: "v2"; router: `0x${string}`; wnative: `0x${string}`; label: string }
  | { kind: "v3"; router: `0x${string}`; wnative: `0x${string}`; fee: number; label: string };

/** Pick the venue with real liquidity: prefer a V3 pool if one exists, else fall back to V2. */
async function detectVenue(fork: AnvilFork, chain: ChainKey, token: `0x${string}`): Promise<Venue | null> {
  const v3 = DEX_V3[chain];
  if (v3) {
    let best: { fee: number; liq: bigint } | null = null;
    for (const fee of V3_FEES) {
      try {
        const pool = (await fork.pub.readContract({ address: v3.factory, abi: V3_FACTORY_ABI, functionName: "getPool", args: [token, v3.wnative, fee] })) as `0x${string}`;
        if (!pool || pool === "0x0000000000000000000000000000000000000000") continue;
        const liq = (await fork.pub.readContract({ address: pool, abi: V3_POOL_ABI, functionName: "liquidity" })) as bigint;
        if (liq > 0n && (!best || liq > best.liq)) best = { fee, liq };
      } catch { /* try next fee */ }
    }
    if (best) return { kind: "v3", router: v3.router, wnative: v3.wnative, fee: best.fee, label: `UniswapV3-${best.fee}` };
  }
  const v2 = DEX[chain];
  if (v2) return { kind: "v2", router: v2.router, wnative: v2.wnative, label: v2.label };
  return null;
}

const DEADLINE = 9_999_999_999n;

export type VectorResult = {
  label: string; // e.g. "size=1eth origin=default"
  boughtOk: boolean;
  buyTax: number | null; // 0..1
  soldOk: boolean;
  sellTax: number | null; // 0..1
  reason?: string;
};

/** Reproducible proof bundle — anyone can re-run the exact simulation and get identical results. */
export type SimProof = {
  chain: ChainKey;
  token: string;
  forkBlock: string; // the exact block the mainnet fork was pinned at
  venue: string; // e.g. "UniswapV3-3000" or "PancakeV2"
  method: "multi_vector_buy_sell_fork";
  replay: string; // command anyone can run to reproduce
};

export type HoneypotResult = {
  chain: ChainKey;
  token: string;
  simulated: boolean;
  hasPair: boolean;
  isHoneypot: boolean; // could buy but cannot sell (any vector)
  selectiveHoneypot: boolean; // some origins sell, others cannot
  maxBuyTax: number | null;
  maxSellTax: number | null;
  taxModifiableAcrossVectors: boolean; // tax differs by origin/size => suspicious
  vectors: VectorResult[];
  proof: SimProof | null; // replayable reproducibility bundle
  observed_at: string;
  error?: string;
};

async function robustApprove(
  fork: AnvilFork, wallet: WalletClient, token: `0x${string}`, router: `0x${string}`
): Promise<boolean> {
  // Some tokens (USDT) require resetting allowance to 0 before setting a new non-zero value.
  const tryApprove = async (amt: bigint) => {
    const h = await wallet.writeContract({ address: token, abi: ERC20_ABI, functionName: "approve", args: [router, amt], account: wallet.account!, chain: null });
    const r = await fork.pub.waitForTransactionReceipt({ hash: h });
    return r.status === "success";
  };
  try {
    if (await tryApprove(maxUint256)) return true;
  } catch { /* fall through to reset pattern */ }
  try {
    await tryApprove(0n);
    return await tryApprove(maxUint256);
  } catch {
    return false;
  }
}

async function buySellVector(
  fork: AnvilFork,
  wallet: WalletClient,
  buyer: `0x${string}`,
  token: `0x${string}`,
  wnative: `0x${string}`,
  router: `0x${string}`,
  ethIn: bigint,
  label: string,
  measure: `0x${string}`
): Promise<VectorResult> {
  const pub = fork.pub;
  await fork.setBalance(measure, 0n);
  try {
    // expected tokens out for buy
    let expectedTokens = 0n;
    try {
      const amts = (await pub.readContract({ address: router, abi: ROUTER_ABI, functionName: "getAmountsOut", args: [ethIn, [wnative, token]] })) as bigint[];
      expectedTokens = amts[1] ?? 0n;
    } catch {
      return { label, boughtOk: false, buyTax: null, soldOk: false, sellTax: null, reason: "no route/pair for buy" };
    }
    if (expectedTokens === 0n) return { label, boughtOk: false, buyTax: null, soldOk: false, sellTax: null, reason: "zero expected out" };

    // BUY
    const buyHash = await wallet.writeContract({
      address: router, abi: ROUTER_ABI, functionName: "swapExactETHForTokensSupportingFeeOnTransferTokens",
      args: [0n, [wnative, token], buyer, DEADLINE], value: ethIn, account: wallet.account!, chain: null,
    });
    const buyRcpt = await pub.waitForTransactionReceipt({ hash: buyHash });
    if (buyRcpt.status !== "success") return { label, boughtOk: false, buyTax: null, soldOk: false, sellTax: null, reason: "buy reverted" };

    const tokenBal = (await pub.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [buyer] })) as bigint;
    if (tokenBal === 0n) return { label, boughtOk: false, buyTax: 1, soldOk: false, sellTax: null, reason: "received 0 tokens (100% buy tax / trap)" };
    const buyTax = clamp01(1 - Number(tokenBal) / Number(expectedTokens));

    // expected ETH out for sell
    let expectedEth = 0n;
    try {
      const amts = (await pub.readContract({ address: router, abi: ROUTER_ABI, functionName: "getAmountsOut", args: [tokenBal, [token, wnative]] })) as bigint[];
      expectedEth = amts[1] ?? 0n;
    } catch { /* still try the sell */ }

    // APPROVE (robust: handles USDT-style reset-to-zero requirement)
    const approved = await robustApprove(fork, wallet, token, router);
    if (!approved) return { label, boughtOk: true, buyTax, soldOk: false, sellTax: null, reason: "approve failed (non-standard token)" };

    // SELL (ETH to clean sink `measure` so we read exact ethOut without gas noise)
    try {
      const sellHash = await wallet.writeContract({
        address: router, abi: ROUTER_ABI, functionName: "swapExactTokensForETHSupportingFeeOnTransferTokens",
        args: [tokenBal, 0n, [token, wnative], measure, DEADLINE], account: wallet.account!, chain: null,
      });
      const sellRcpt = await pub.waitForTransactionReceipt({ hash: sellHash });
      if (sellRcpt.status !== "success") return { label, boughtOk: true, buyTax, soldOk: false, sellTax: null, reason: "SELL REVERTED (honeypot)" };
    } catch (e: any) {
      return { label, boughtOk: true, buyTax, soldOk: false, sellTax: null, reason: "SELL REVERTED (honeypot): " + (e?.shortMessage ?? e?.message ?? "") };
    }
    const ethOut = await pub.getBalance({ address: measure });
    const sellTax = expectedEth > 0n ? clamp01(1 - Number(ethOut) / Number(expectedEth)) : null;
    return { label, boughtOk: true, buyTax, soldOk: true, sellTax };
  } catch (e: any) {
    return { label, boughtOk: false, buyTax: null, soldOk: false, sellTax: null, reason: e?.shortMessage ?? e?.message ?? String(e) };
  }
}

/** V3 buy/sell via exactInputSingle. Honeypot detection focus (boughtOk/soldOk); tax from static/GoPlus. */
async function buySellVectorV3(
  fork: AnvilFork, wallet: WalletClient, buyer: `0x${string}`,
  token: `0x${string}`, wnative: `0x${string}`, router: `0x${string}`, fee: number,
  ethIn: bigint, label: string, measure: `0x${string}`
): Promise<VectorResult> {
  const pub = fork.pub;
  await fork.setBalance(measure, 0n);
  try {
    // BUY
    try {
      const h = await wallet.writeContract({
        address: router, abi: V3_ROUTER_ABI, functionName: "exactInputSingle",
        args: [{ tokenIn: wnative, tokenOut: token, fee, recipient: buyer, amountIn: ethIn, amountOutMinimum: 0n, sqrtPriceLimitX96: 0n }],
        value: ethIn, account: wallet.account!, chain: null,
      });
      const r = await pub.waitForTransactionReceipt({ hash: h });
      if (r.status !== "success") return { label, boughtOk: false, buyTax: null, soldOk: false, sellTax: null, reason: "buy reverted (v3)" };
    } catch (e: any) {
      return { label, boughtOk: false, buyTax: null, soldOk: false, sellTax: null, reason: "buy reverted (v3): " + (e?.shortMessage ?? "") };
    }
    const tokenBal = (await pub.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [buyer] })) as bigint;
    if (tokenBal === 0n) return { label, boughtOk: false, buyTax: 1, soldOk: false, sellTax: null, reason: "received 0 tokens (trap)" };

    if (!(await robustApprove(fork, wallet, token, router))) return { label, boughtOk: true, buyTax: null, soldOk: false, sellTax: null, reason: "approve failed" };

    // SELL (WETH to clean sink; presence of WETH balance = sold)
    try {
      const h = await wallet.writeContract({
        address: router, abi: V3_ROUTER_ABI, functionName: "exactInputSingle",
        args: [{ tokenIn: token, tokenOut: wnative, fee, recipient: measure, amountIn: tokenBal, amountOutMinimum: 0n, sqrtPriceLimitX96: 0n }],
        account: wallet.account!, chain: null,
      });
      const r = await pub.waitForTransactionReceipt({ hash: h });
      if (r.status !== "success") return { label, boughtOk: true, buyTax: null, soldOk: false, sellTax: null, reason: "SELL REVERTED (honeypot, v3)" };
    } catch (e: any) {
      return { label, boughtOk: true, buyTax: null, soldOk: false, sellTax: null, reason: "SELL REVERTED (honeypot, v3): " + (e?.shortMessage ?? "") };
    }
    const wethOut = (await pub.readContract({ address: wnative, abi: ERC20_ABI, functionName: "balanceOf", args: [measure] })) as bigint;
    if (wethOut === 0n) return { label, boughtOk: true, buyTax: null, soldOk: false, sellTax: 1, reason: "sold but received 0 (100% sell tax)" };
    // approximate round-trip retention → high loss beyond fees flags heavy tax
    const retention = Number(wethOut) / Number(ethIn);
    const sellTax = retention < 0.85 ? clamp01(1 - retention - fee / 1_000_000) : 0;
    return { label, boughtOk: true, buyTax: null, soldOk: true, sellTax };
  } catch (e: any) {
    return { label, boughtOk: false, buyTax: null, soldOk: false, sellTax: null, reason: e?.shortMessage ?? e?.message ?? String(e) };
  }
}

/** Multi-vector honeypot simulation: multiple sizes × multiple origins (incl. a fresh EOA).
 *  Auto-selects V3 (preferred, by liquidity) or V2 venue. Pass `existingFork` for deterministic tests. */
export async function simulateHoneypot(chain: ChainKey, token: `0x${string}`, existingFork?: AnvilFork): Promise<HoneypotResult> {
  const observed_at = new Date().toISOString();

  const fork = existingFork ?? new AnvilFork(chain);
  try {
    if (!existingFork) await fork.start();
    const venue = await detectVenue(fork, chain, token);
    if (!venue) return { chain, token, simulated: false, hasPair: false, isHoneypot: false, selectiveHoneypot: false, maxBuyTax: null, maxSellTax: null, taxModifiableAcrossVectors: false, vectors: [], proof: null, observed_at, error: `no DEX venue with liquidity for ${chain}` };
    const sizes: Array<[string, bigint]> = chain === "bsc"
      ? [["0.5", parseEther("0.5")], ["2", parseEther("2")]]
      : [["0.1", parseEther("0.1")], ["1", parseEther("1")]];

    const vectors: VectorResult[] = [];
    const fundWei = parseEther(chain === "bsc" ? "10" : "5");

    const matrix: Array<[string, bigint]> = [
      [`size=${sizes[0]![0]} origin=A`, sizes[0]![1]],
      [`size=${sizes[1]![0]} origin=B`, sizes[1]![1]],
      [`size=${sizes[0]![0]} origin=C`, sizes[0]![1]], // second same-size, different origin => selective-honeypot check
    ];

    // Snapshot isolation: every vector runs from identical pristine forked state (no cross-vector
    // contamination). `pristine` always points at a fresh snapshot of the post-fork state.
    let pristine = await fork.snapshot();
    const runIsolated = async (fn: () => Promise<VectorResult>): Promise<VectorResult> => {
      await fork.revert(pristine);
      pristine = await fork.snapshot();
      return fn();
    };
    const doVector = async (label: string, wei: bigint, idx: number): Promise<VectorResult> => {
      const buyer = await fork.freshWallet(fundWei);
      const measure = (`0x${(((idx % 50) + 0xa1).toString(16).padStart(2, "0")).repeat(20)}`) as `0x${string}`;
      return venue.kind === "v3"
        ? buySellVectorV3(fork, buyer.client, buyer.address, token, venue.wnative, venue.router, venue.fee, wei, label, measure)
        : buySellVector(fork, buyer.client, buyer.address, token, venue.wnative, venue.router, wei, label, measure);
    };

    let idx = 0;
    for (const [label, wei] of matrix) {
      // A real honeypot fails DETERMINISTICALLY; retry up to 3× and take the BEST outcome, so
      // transient RPC/fork reverts (or a thin V2 pair) can never produce a false honeypot signal.
      let r = await runIsolated(() => doVector(label, wei, idx));
      for (let attempt = 0; attempt < 2 && (r.boughtOk ? !r.soldOk : true); attempt++) {
        const rr = await runIsolated(() => doVector(label, wei, idx));
        if (best(rr) > best(r)) r = rr;
      }
      vectors.push(r);
      idx++;
    }

    const buyable = vectors.filter((v) => v.boughtOk);
    const hasPair = vectors.some((v) => v.reason !== "no route/pair for buy" && (v.boughtOk || v.buyTax !== null));
    const sellable = buyable.filter((v) => v.soldOk);
    const isHoneypot = buyable.length > 0 && sellable.length === 0;
    // Selective honeypot needs a REAL pattern: ≥2 buyers can't sell while ≥1 can. A single (retried)
    // failure never triggers it — false positives on clean tokens are catastrophic.
    const selectiveHoneypot = sellable.length >= 1 && buyable.length - sellable.length >= 2;
    const buyTaxes = vectors.map((v) => v.buyTax).filter((x): x is number => x != null);
    const sellTaxes = vectors.map((v) => v.sellTax).filter((x): x is number => x != null);
    const maxBuyTax = buyTaxes.length ? Math.max(...buyTaxes) : null;
    const maxSellTax = sellTaxes.length ? Math.max(...sellTaxes) : null;
    const taxSpread = sellTaxes.length > 1 ? Math.max(...sellTaxes) - Math.min(...sellTaxes) : 0;
    const taxModifiableAcrossVectors = taxSpread > 0.05;

    const forkBlock = (fork.forkBlockNumber ?? 0n).toString();
    const proof: SimProof = {
      chain, token, forkBlock, venue: venue.label, method: "multi_vector_buy_sell_fork",
      replay: `aletheia replay-sim ${chain} ${token} ${forkBlock}`,
    };
    return { chain, token, simulated: true, hasPair, isHoneypot, selectiveHoneypot, maxBuyTax, maxSellTax, taxModifiableAcrossVectors, vectors, proof, observed_at };
  } catch (e: any) {
    return { chain, token, simulated: false, hasPair: false, isHoneypot: false, selectiveHoneypot: false, maxBuyTax: null, maxSellTax: null, taxModifiableAcrossVectors: false, vectors: [], proof: null, observed_at, error: e?.message ?? String(e) };
  } finally {
    if (!existingFork) await fork.stop();
  }
}

/** Replay a prior honeypot sim at its exact fork block — deterministic reproduction of the proof. */
export async function replaySim(chain: ChainKey, token: `0x${string}`, forkBlock: string | bigint): Promise<HoneypotResult> {
  const fork = new AnvilFork(chain, BigInt(forkBlock));
  await fork.start();
  try {
    return await simulateHoneypot(chain, token, fork);
  } finally {
    await fork.stop();
  }
}

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

/** Rank vector outcomes: bought+sold (best) > bought-only > nothing. Used to pick the best retry. */
function best(v: VectorResult): number {
  if (v.boughtOk && v.soldOk) return 2;
  if (v.boughtOk) return 1;
  return 0;
}
