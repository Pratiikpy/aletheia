import { getTokenSecurity } from "../src/adapters/goplus.js";

// USDT on Ethereum (clean) and a BSC token, to confirm live GoPlus reads.
const cases: Array<[any, string, string]> = [
  ["ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT (should be clean)"],
  ["bsc", "0x55d398326f99059ff775485246999027b3197955", "BSC-USD"],
];

for (const [chain, addr, label] of cases) {
  const r = await getTokenSecurity(chain, addr);
  console.log(`\n=== ${label} [${chain}] ===`);
  console.log("ok:", r.ok, "error:", r.error ?? "-");
  if (r.data) {
    const d = r.data;
    console.log({
      token_name: d.token_name,
      is_open_source: d.is_open_source,
      is_honeypot: d.is_honeypot,
      buy_tax: d.buy_tax,
      sell_tax: d.sell_tax,
      is_mintable: d.is_mintable,
      is_proxy: d.is_proxy,
      owner_address: d.owner_address,
      holder_count: d.holder_count,
      slippage_modifiable: d.slippage_modifiable,
      hidden_owner: d.hidden_owner,
      can_take_back_ownership: d.can_take_back_ownership,
    });
  }
}
