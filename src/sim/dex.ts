import type { ChainKey } from "../config.js";

/** Per-chain V2-style router + wrapped-native base token used for buy/sell simulation. */
export const DEX: Partial<Record<ChainKey, { router: `0x${string}`; wnative: `0x${string}`; label: string }>> = {
  ethereum: {
    router: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", // Uniswap V2
    wnative: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
    label: "UniswapV2",
  },
  bsc: {
    router: "0x10ED43C718714eb63d5aA57B78B54704E256024E", // PancakeSwap V2
    wnative: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", // WBNB
    label: "PancakeV2",
  },
  base: {
    router: "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24", // Uniswap V2 (Base)
    wnative: "0x4200000000000000000000000000000000000006", // WETH (Base)
    label: "UniswapV2-Base",
  },
} as const;

export const ROUTER_ABI = [
  {
    type: "function",
    name: "swapExactETHForTokensSupportingFeeOnTransferTokens",
    stateMutability: "payable",
    inputs: [
      { name: "amountOutMin", type: "uint256" },
      { name: "path", type: "address[]" },
      { name: "to", type: "address" },
      { name: "deadline", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "swapExactTokensForETHSupportingFeeOnTransferTokens",
    stateMutability: "nonpayable",
    inputs: [
      { name: "amountIn", type: "uint256" },
      { name: "amountOutMin", type: "uint256" },
      { name: "path", type: "address[]" },
      { name: "to", type: "address" },
      { name: "deadline", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "getAmountsOut",
    stateMutability: "view",
    inputs: [
      { name: "amountIn", type: "uint256" },
      { name: "path", type: "address[]" },
    ],
    outputs: [{ name: "amounts", type: "uint256[]" }],
  },
] as const;

/** Uniswap V3 (same addresses on ETH/Arbitrum/Polygon; Base differs). Fee tiers checked in depth order. */
export const DEX_V3: Partial<Record<ChainKey, { router: `0x${string}`; factory: `0x${string}`; wnative: `0x${string}` }>> = {
  ethereum: { router: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", factory: "0x1F98431c8aD98523631AE4a59f267346ea31F984", wnative: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" },
  arbitrum: { router: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", factory: "0x1F98431c8aD98523631AE4a59f267346ea31F984", wnative: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1" },
  polygon: { router: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", factory: "0x1F98431c8aD98523631AE4a59f267346ea31F984", wnative: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270" },
  base: { router: "0x2626664c2603336E57B271c5C0b26F421741e481", factory: "0x33128a8fC17869897dcE68Ed026d694621f6FDfD", wnative: "0x4200000000000000000000000000000000000006" },
};
export const V3_FEES = [3000, 500, 10000, 100] as const;

export const V3_FACTORY_ABI = [
  { type: "function", name: "getPool", stateMutability: "view", inputs: [{ type: "address" }, { type: "address" }, { type: "uint24" }], outputs: [{ type: "address" }] },
] as const;
export const V3_POOL_ABI = [
  { type: "function", name: "liquidity", stateMutability: "view", inputs: [], outputs: [{ type: "uint128" }] },
] as const;
export const V3_ROUTER_ABI = [
  {
    type: "function", name: "exactInputSingle", stateMutability: "payable",
    inputs: [{ components: [
      { name: "tokenIn", type: "address" }, { name: "tokenOut", type: "address" }, { name: "fee", type: "uint24" },
      { name: "recipient", type: "address" }, { name: "amountIn", type: "uint256" }, { name: "amountOutMinimum", type: "uint256" }, { name: "sqrtPriceLimitX96", type: "uint160" },
    ], name: "params", type: "tuple" }],
    outputs: [{ name: "amountOut", type: "uint256" }],
  },
] as const;

export const ERC20_ABI = [
  { type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ name: "s", type: "address" }, { name: "a", type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ name: "o", type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "a", type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
] as const;
