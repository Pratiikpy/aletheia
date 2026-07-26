import { alchemyRpc, type ChainKey } from "../config.js";

/**
 * Airdrop / sybil-farming intelligence — "is this wallet a real user or a farmed sybil?".
 *
 * Airdrop teams and protocols bleed value to sybil farmers who spin up hundreds of wallets from one
 * funding hub, do minimal activity, then claim and dump. We score a wallet's farming footprint from
 * free on-chain signals: how many OTHER wallets share its first funder (a hub fanning out to many fresh
 * wallets is the classic sybil seeder), how thin its own activity is, and how new it is. Keyless
 * (Alchemy transfer history); the scoring is pure and unit-tested.
 */

export type SybilCheck = {
  ok: boolean;
  observed_at: string;
  wallet: string;
  chain: ChainKey;
  funder: string | null;
  funderFanout: number; // distinct wallets this funder seeded (sampled)
  txCount: number | null; // wallet nonce — organic activity level
  ageDays: number | null; // days since first funded
  sybilScore: number; // 0..1
  label: "LIKELY_SYBIL" | "MIXED" | "LIKELY_ORGANIC";
  reasons: string[];
  error?: string;
};

async function rpc(chain: ChainKey, method: string, params: any[]): Promise<any> {
  const res = await fetch(alchemyRpc(chain), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(30_000) });
  const j: any = await res.json();
  if (j.error) throw new Error(j.error.message ?? "rpc error");
  return j.result;
}

/** Score the sybil-farming footprint from the raw signals (pure, unit-testable). */
export function scoreSybil(input: { funderFanout: number; txCount: number | null; ageDays: number | null }): { sybilScore: number; label: SybilCheck["label"]; reasons: string[] } {
  const { funderFanout, txCount, ageDays } = input;
  const reasons: string[] = [];
  let score = 0;

  // 1. shared funding hub — the strongest sybil signal
  if (funderFanout >= 100) { score += 0.5; reasons.push(`funded by a hub that seeded ${funderFanout}+ wallets`); }
  else if (funderFanout >= 30) { score += 0.35; reasons.push(`funder seeded ${funderFanout} wallets`); }
  else if (funderFanout >= 10) { score += 0.2; reasons.push(`funder seeded ${funderFanout} wallets`); }

  // 2. thin organic activity — farmers do the minimum
  if (txCount != null) {
    if (txCount <= 5) { score += 0.3; reasons.push(`only ${txCount} lifetime transactions`); }
    else if (txCount <= 20) { score += 0.15; reasons.push(`low activity (${txCount} txns)`); }
    else reasons.push(`${txCount} txns — meaningful activity`);
  }

  // 3. very new wallet
  if (ageDays != null && ageDays < 30 && (txCount ?? 0) <= 20) { score += 0.2; reasons.push(`wallet is only ${Math.round(ageDays)} days old`); }

  score = Math.min(1, score);
  const label = score >= 0.6 ? "LIKELY_SYBIL" : score >= 0.3 ? "MIXED" : "LIKELY_ORGANIC";
  return { sybilScore: score, label, reasons };
}

async function firstFunder(chain: ChainKey, wallet: string): Promise<{ funder: string | null; ts: number | null }> {
  const r = await rpc(chain, "alchemy_getAssetTransfers", [{ toAddress: wallet, category: ["external", "erc20"], order: "asc", maxCount: "0x1", withMetadata: true }]).catch(() => null);
  const first = r?.transfers?.[0];
  const ts = first?.metadata?.blockTimestamp ? Math.floor(new Date(first.metadata.blockTimestamp).getTime() / 1000) : null;
  return { funder: first?.from ? String(first.from).toLowerCase() : null, ts };
}

/** Count distinct wallets a funder has sent native/token to (sampled) — its fan-out. */
async function funderFanout(chain: ChainKey, funder: string): Promise<number> {
  const r = await rpc(chain, "alchemy_getAssetTransfers", [{ fromAddress: funder, category: ["external"], order: "asc", maxCount: "0x1f4", withMetadata: false }]).catch(() => null);
  const recips = new Set<string>();
  for (const t of r?.transfers ?? []) if (t.to) recips.add(String(t.to).toLowerCase());
  return recips.size;
}

const CHAINS_WITH_TRANSFERS = new Set<ChainKey>(["ethereum", "bsc", "base", "arbitrum", "polygon"]);
// exchanges/routers fan out to huge numbers of wallets legitimately — not sybil hubs
const NEUTRAL_FUNDERS = new Set([
  "0x28c6c06298d514db089934071355e5743bf21d60", "0x21a31ee1afc51d94c2efccaa2092ad1028285549",
  "0xdfd5293d8e347dfe59e90efd55b2956a1343963d", "0x56eddb7aa87536c09ccc2793473599fd21a8b17f",
  "0x9696f59e4d72e237be84ffd425dcad154bf96976", "0xf977814e90da44bfa03b6295a0616a897441acec",
  "0x71660c4005ba85c37ccec55d0c4493e66fe775d3", "0x503828976d22510aad0201ac7ec88293211d23da",
  "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740", "0x0000000000000000000000000000000000000000",
]);

export async function airdropSybilCheck(chain: ChainKey, wallet: string): Promise<SybilCheck> {
  const observed_at = new Date().toISOString();
  const base: SybilCheck = { ok: false, observed_at, wallet, chain, funder: null, funderFanout: 0, txCount: null, ageDays: null, sybilScore: 0, label: "LIKELY_ORGANIC", reasons: [] };
  if (!CHAINS_WITH_TRANSFERS.has(chain)) return { ...base, error: "transfer history unavailable on this chain" };
  if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) return { ...base, error: "invalid wallet address" };
  const w = wallet.toLowerCase();
  try {
    const [{ funder, ts }, nonceHex] = await Promise.all([
      firstFunder(chain, w),
      rpc(chain, "eth_getTransactionCount", [w, "latest"]).catch(() => null),
    ]);
    const txCount = nonceHex != null ? parseInt(nonceHex, 16) : null;
    const ageDays = ts != null ? (Date.now() / 1000 - ts) / 86400 : null;
    // only measure fan-out for non-exchange funders (a CEX seeding many wallets isn't sybil)
    const fanout = funder && !NEUTRAL_FUNDERS.has(funder) ? await funderFanout(chain, funder).catch(() => 0) : 0;
    const neutralNote = funder && NEUTRAL_FUNDERS.has(funder) ? ["funded directly by an exchange (not a sybil hub)"] : [];

    const { sybilScore, label, reasons } = scoreSybil({ funderFanout: fanout, txCount, ageDays });
    return { ok: true, observed_at, wallet: w, chain, funder, funderFanout: fanout, txCount, ageDays: ageDays != null ? Math.round(ageDays) : null, sybilScore, label, reasons: [...neutralNote, ...reasons] };
  } catch (e: any) {
    return { ...base, wallet: w, error: e?.message ?? String(e) };
  }
}
