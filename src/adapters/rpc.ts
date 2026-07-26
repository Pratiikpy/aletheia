import { createPublicClient, http, type PublicClient } from "viem";
import { alchemyRpc, CHAINS, type ChainKey } from "../config.js";

const clients = new Map<ChainKey, PublicClient>();

export function evmClient(chain: ChainKey): PublicClient {
  let c = clients.get(chain);
  if (!c) {
    c = createPublicClient({
      transport: http(alchemyRpc(chain), { batch: true, retryCount: 2 }),
    }) as PublicClient;
    clients.set(chain, c);
  }
  return c;
}

export async function chainTip(chain: ChainKey): Promise<{ blockNumber: bigint; chainId: number }> {
  const client = evmClient(chain);
  const [blockNumber, chainId] = await Promise.all([client.getBlockNumber(), client.getChainId()]);
  return { blockNumber, chainId };
}

/** Basic ERC-20 metadata via multicall-friendly reads. */
const ERC20_ABI = [
  { type: "function", name: "name", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "symbol", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
  { type: "function", name: "totalSupply", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
] as const;

export async function erc20Meta(chain: ChainKey, address: `0x${string}`) {
  const client = evmClient(chain);
  const observed_at = new Date().toISOString();
  try {
    const [name, symbol, decimals, totalSupply, bytecode] = await Promise.all([
      client.readContract({ address, abi: ERC20_ABI, functionName: "name" }).catch(() => undefined),
      client.readContract({ address, abi: ERC20_ABI, functionName: "symbol" }).catch(() => undefined),
      client.readContract({ address, abi: ERC20_ABI, functionName: "decimals" }).catch(() => undefined),
      client.readContract({ address, abi: ERC20_ABI, functionName: "totalSupply" }).catch(() => undefined),
      client.getBytecode({ address }).catch(() => undefined),
    ]);
    return {
      ok: true,
      observed_at,
      name: name as string | undefined,
      symbol: symbol as string | undefined,
      decimals: decimals as number | undefined,
      totalSupply: totalSupply as bigint | undefined,
      isContract: !!bytecode && bytecode !== "0x",
      bytecodeSize: bytecode ? (bytecode.length - 2) / 2 : 0,
    };
  } catch (e: any) {
    return { ok: false, observed_at, error: e?.message ?? String(e) };
  }
}

export { CHAINS };
