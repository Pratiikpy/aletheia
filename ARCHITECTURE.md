# Verity — Architecture

The fused pre-trade intelligence ASP. One call → one evidence-linked verdict. Best-in-class, no-compromise stack.

## Principles
- **Every feature passes a usefulness gate** (changes a real decision) and an A-tier bar, or it's cut. No dead weight.
- **Evidence on every line.** No claim without a source/simulation/citation + freshness stamp. (Audit-proven differentiator; kills the "sources can't be verified" ceiling.)
- **Reliability first.** Flawless single-call delivery — buyers 1★ empty/failed output. ≥99% clean delivery target.
- **Fusion is the product**, raw data is sourced. We build the intelligence layer (sim, fusion, scoreboard); OKX/GoPlus provide raw data.

## Stack (best-fit, decided)
- **Runtime:** Node 22, TypeScript (ESM). 0G SDK is TS, OKX x402 SDK is Node, MCP SDK is TS — TS is the correct home.
- **Validation/schema:** Zod (the verdict envelope is a Zod schema = single source of truth, runtime-validated).
- **HTTP API:** Hono (fast, typed, portable).
- **MCP server:** `@modelcontextprotocol/sdk` — exposes `verdict` + sub-tools so agents compose us.
- **EVM chain reads + sim:** viem; multi-vector honeypot sim via local **anvil fork** (Foundry) at chain tip, forked over Alchemy RPC.
- **Solana reads:** @solana/web3.js over Helius.
- **AI brain:** 0G Compute router (OpenAI-compatible) — model router: cheap (`deepseek-v4-flash`) for flag tier, strong (`minimax-m3`/`glm-5.2`) for reports, parallel jury for bull/bear.
- **Payments:** `@okxweb3/x402-express` — per-call USDG/USDT, zero gas on X Layer (eip155:196).
- **DB:** Postgres (Neon free / droplet) via Drizzle — reputation, verdict history, accuracy scoreboard, monitoring state. Dev: local sqlite fallback.
- **Tests:** Vitest. Every adapter + engine has a live-data test.

## Module layout (src/)
```
config.ts            env + model routing config
types/verdict.ts     THE envelope (Zod) — verdict/score/confidence/dimensions/signals/evidence/freshness/provenance/cost
adapters/            raw-data sources, each returns typed + freshness-stamped data
  okx.ts             Onchain OS: token info, holder clusters, bundle/sniper, smart-money, PnL, WS
  goplus.ts          security fields (free breadth)
  rpc.ts             viem/EVM + Helius/Solana clients
sim/                 OUR MOAT
  honeypot.ts        multi-vector fork simulation (sizes × origins × future-block × transfer)
engine/              OUR MOAT
  dimensions/        one scorer per domain (security, market, smart_money, tokenomics, social, research)
  fuse.ts            weighted composite, red-flag caps, confidence calibration
  explain.ts         0G-written plain-English + per-line evidence linkage
  verdict.ts         orchestrator → the envelope
scoreboard/          accuracy tracking vs labeled sets + vs named incumbents (the trust moat)
ai/router.ts         0G model router (cheap/strong/jury)
mcp/server.ts        MCP tools
api/server.ts        Hono HTTP + x402 payment gate
monitor/             watch-my-bag (WS subscribe → reasoned mini-briefs)
```

## The verdict pipeline (per call)
1. Resolve subject (chain, address) → pick depth tier (flag/full/deep).
2. Fan out adapters in parallel (OKX + GoPlus + RPC) + run multi-vector sim (full/deep).
3. Each dimension scorer produces {verdict, score, signals[] with evidence[] + confidence}.
4. `fuse.ts` → composite verdict + calibrated confidence; hard security flags cap it.
5. `explain.ts` (0G) → plain-English summary; every line linked to a signal's evidence.
6. Emit the Zod-validated envelope; log to scoreboard; charge via x402.

## Ownership gate (per feature, enforced in build)
Each feature ships only when: (a) it changes a real user decision (else cut), (b) it hits its A-tier bar, (c) every output line carries evidence. Tracked in FEATURES.md.
