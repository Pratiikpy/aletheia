import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { tokenVerdict, tokenVerdictDeep, tokenVerdictCourtroom } from "../engine/verdict.js";
import { walletPnl } from "../engine/pnl.js";
import { solanaVerdict } from "../engine/solana.js";
import { resolveOutcome } from "../engine/resolver.js";
import { evaluateTx } from "../engine/firewall.js";
import { guardWallet } from "../engine/guardian.js";
import { copyIntel } from "../engine/copytrade.js";
import { taxReport } from "../engine/tax.js";
import { auditAgent } from "../audit/audit.js";
import { proveFact } from "../evidence/prove.js";
import { socialPulse } from "../pulse/pulse.js";
import { repoRadar } from "../repo/radar.js";
import { scanContent } from "../actionguard/promptfw.js";
import { copySignal } from "../actionguard/copysignal.js";
import { trenchScan } from "../actionguard/trench.js";
import { verifyOutput } from "../actionguard/verifier.js";
import { reviewDoc } from "../actionguard/docreview.js";
import { preTxGuardian } from "../actionguard/pretx.js";
import { checkCounterparty } from "../actionguard/counterparty.js";
import { huntImpersonation } from "../actionguard/impersonation.js";
import { actionGuard } from "../actionguard/actionguard.js";
import { airdropSybilCheck } from "../engine/airdrop.js";
import { simulateHoneypot, replaySim } from "../sim/honeypot.js";
import { snapshotOf, diffSnapshots, type Snapshot } from "../monitor/watch.js";
import { CHAINS, type ChainKey } from "../config.js";

const CHAIN_KEYS = Object.keys(CHAINS) as [ChainKey, ...ChainKey[]];

export function buildMcpServer(): McpServer {
  const server = new McpServer({ name: "aletheia", version: "0.1.0" });

  server.tool(
    "aletheia_token_verdict",
    "Get Aletheia's fused, evidence-linked pre-trade verdict (GO/CAUTION/AVOID) for a token: security + risk fused across a multi-vector honeypot simulation and static analysis, with a confidence score and citations. Use before an agent buys or recommends any token.",
    {
      chain: z.enum(CHAIN_KEYS).describe("EVM chain the token is on"),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("token contract address"),
      tier: z.enum(["flag", "full", "deep"]).default("full").describe("flag=fast static, full=+multi-vector simulation, deep=+committee report"),
    },
    async ({ chain, address, tier }) => {
      const v = await tokenVerdict(chain as ChainKey, address, tier);
      return { content: [{ type: "text", text: JSON.stringify(v, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_repo_radar",
    "RepoRadar: GitHub due diligence for a project's codebase → LEGIT / COSMETIC / RED_FLAG with evidence. From cheap gh-API signals (star-vs-contributor imbalance = star-botting, single-dump commit history, tests/CI presence, staleness, README claims vs apparent code). Use to vet a crypto/software project's repo before investing or integrating.",
    {
      repo: z.string().describe("a GitHub repo — owner/name, or a full github.com URL"),
    },
    async ({ repo }) => {
      const r = await repoRadar(repo);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_social_pulse",
    "Social Pulse: cross-platform sentiment for a token/topic (Twitter + Reddit + YouTube) → HYPE / ORGANIC / DEAD, with sentiment, a buzz score, red flags (coordinated shilling, spam), and a live-source breakdown. Degrades gracefully if a source is down. Use to gauge whether chatter is real organic interest, manufactured hype, or nothing at all.",
    {
      query: z.string().min(2).describe("token symbol, name, or topic to gauge (e.g. 'PEPE', 'wif coin')"),
    },
    async ({ query }) => {
      const r = await socialPulse(query);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_prove_fact",
    "Verified-evidence: ground a claim in a real source before acting on it. Give a URL and a question → Aletheia fetches the page, hashes the exact bytes (a timestamped snapshot proof), extracts the answer with a no-fabrication model, and confirms the answer's snippet is a verbatim substring of the page (so it can't be hallucinated). Returns found/value/snippet + a content hash anyone can re-verify.",
    {
      url: z.string().url().describe("the source URL to fetch and prove against"),
      query: z.string().describe("the factual question to answer from that URL"),
    },
    async ({ url, query }) => {
      const r = await proveFact(url, query);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_prompt_firewall",
    "Prompt Firewall: scan a piece of untrusted/retrieved content (a web page, document, or MCP tool result) for prompt-injection BEFORE your agent follows it. Returns SAFE / SUSPICIOUS / INJECTION with the matched attack patterns as evidence. Call on any content an agent is about to act on.",
    { content: z.string().describe("the retrieved/untrusted content to scan") },
    async ({ content }) => {
      const r = scanContent(content);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_copy_signal",
    "Copy-signal: what is smart money doing on a token right now? Reads OKX Onchain OS smart-money signals + top profitable traders → SMART_MONEY_BUYING / MIXED / SMART_MONEY_EXITING / QUIET. Use to gauge informed flow before entering.",
    { chain: z.enum(CHAIN_KEYS), address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("token contract") },
    async ({ chain, address }) => {
      const r = await copySignal(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_trench_scan",
    "Trench scanner: pre-buy due diligence for a fresh launch (pump.fun-style). Reads OKX memepump data — dev holding %, bundled-at-launch %, sniper ratio, dev prior-rug history → SAFE_LAUNCH / RISKY_LAUNCH / RUG_SETUP. Use before aping a new token.",
    { chain: z.enum(CHAIN_KEYS), address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("launch token contract") },
    async ({ chain, address }) => {
      const r = await trenchScan(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_actionguard",
    "ActionGuard: the pre-action firewall an agent calls BEFORE it acts. Composes transaction guardian + counterparty check + prompt firewall + data-loss prevention into ONE signed ALLOW / REVIEW / BLOCK decision with evidence and a hashed decision trace. Pass a transaction, a piece of content, or a counterparty address.",
    {
      type: z.enum(["transaction", "content", "counterparty"]),
      chain: z.enum(CHAIN_KEYS).optional(),
      to: z.string().optional(), data: z.string().optional(), value: z.string().optional(), payload: z.string().optional(),
      content: z.string().optional(), url: z.string().optional(),
      address: z.string().optional(),
    },
    async (a) => {
      const r = await actionGuard(a as any);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_counterparty_check",
    "Counterparty check: vet an address/service/wallet before transacting with it. Flags known-malicious (phishing/scam/sanctioned), throwaway/fresh wallets, and reads on-chain footprint → FLAGGED / THIN / CLEAR. (Proves bad; a clean result is not proof of trust.)",
    { chain: z.enum(CHAIN_KEYS), address: z.string().regex(/^0x[a-fA-F0-9]{40}$/) },
    async ({ chain, address }) => {
      const r = await checkCounterparty(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_impersonation_hunt",
    "Brand-impersonation hunter: find live lookalikes of a brand before trusting a link/handle. Generates typosquat domain variants of the official domain and checks which actually resolve, plus a social-handle scan → IMPERSONATORS_FOUND / CLEAR.",
    { brand: z.string(), official_domain: z.string().optional().describe("e.g. okx.com — enables domain typosquat scanning") },
    async ({ brand, official_domain }) => {
      const r = await huntImpersonation(brand, official_domain);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_verify_output",
    "AI Output Verifier: before trusting another agent's answer, cross-check it with multiple independent 0G models. Returns VERIFIED / DISPUTED / LIKELY_WRONG + confidence + flagged unsupported claims. Use to validate an answer, summary, or extracted fact before acting on it.",
    { question: z.string().describe("the question/task the answer responds to"), answer: z.string().describe("the answer/output to verify") },
    async ({ question, answer }) => {
      const r = await verifyOutput(question, answer);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_review_document",
    "Contract/Invoice Risk Reviewer: analyze a document (raw text or a URL) for dangerous clauses, missing protections, and unusual terms. Returns LOW/MEDIUM/HIGH risk with flagged clauses. Use before signing/paying.",
    { text: z.string().optional().describe("the document text"), url: z.string().url().optional().describe("a URL to fetch the document from") },
    async ({ text, url }) => {
      const r = await reviewDoc({ text, url });
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_pretx_guardian",
    "Pre-Transaction Guardian: before an agent signs, decode a transaction, state its expected token/permission changes in plain language, run the firewall (malicious counterparty, unlimited approval, AVOID token), and return ALLOW / REVIEW / BLOCK. Call before signing any tx.",
    {
      chain: z.enum(CHAIN_KEYS),
      to: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
      data: z.string().optional(),
      value: z.string().optional(),
    },
    async ({ chain, to, data, value }) => {
      const r = await preTxGuardian(chain as ChainKey, { to, data, value });
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_agent_audit",
    "AgentAudit: trust-score another AI agent / ASP before hiring it. Point at any OpenAI-compatible chat endpoint → Aletheia probes it (injection & jailbreak resistance, accuracy, latency, cost) and returns a signed GO/CAUTION/AVOID scorecard with evidence on every probe. Use before delegating work or paying another agent.",
    {
      endpoint: z.string().url().describe("the target agent's OpenAI-compatible base URL (we append /chat/completions)"),
      model: z.string().describe("the model/agent name to send in the request"),
      api_key: z.string().optional().describe("bearer token for the target, if it requires auth"),
      system: z.string().optional().describe("the system prompt the target runs under (probed for leakage)"),
      pricing_input_per_m: z.number().optional().describe("target's input price per 1M tokens (USD) — enables cost scoring"),
      pricing_output_per_m: z.number().optional().describe("target's output price per 1M tokens (USD)"),
    },
    async ({ endpoint, model, api_key, system, pricing_input_per_m, pricing_output_per_m }) => {
      const r = await auditAgent(
        { baseUrl: endpoint, model, apiKey: api_key, system },
        { pricing: { inputPerM: pricing_input_per_m, outputPerM: pricing_output_per_m } }
      );
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_solana_token_verdict",
    "Get Aletheia's fused pre-trade verdict (GO/CAUTION/AVOID) for a SOLANA SPL token: freeze/mint authority, Token-2022 extensions (transfer-fee, transfer-hook, permanent-delegate), holder concentration, and a live Jupiter buy/sell route check (the Solana honeypot test). Use before an agent buys or recommends any SPL token.",
    {
      mint: z.string().min(32).max(44).describe("SPL token mint address (base58)"),
      tier: z.enum(["flag", "full"]).default("full").describe("flag=authorities+holders only, full=+Jupiter tradeability"),
    },
    async ({ mint, tier }) => {
      const v = await solanaVerdict(mint, tier);
      return { content: [{ type: "text", text: JSON.stringify(v, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_honeypot_check",
    "Run Aletheia's multi-vector honeypot simulation on a token (multiple trade sizes and origins on a mainnet fork) and return whether it is buyable/sellable, the measured buy/sell tax, and whether it is a honeypot or selective honeypot.",
    {
      chain: z.enum(CHAIN_KEYS).describe("EVM chain"),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("token contract address"),
    },
    async ({ chain, address }) => {
      const r = await simulateHoneypot(chain as ChainKey, address as `0x${string}`);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_deep_report",
    "Get Aletheia's deep committee research report for a token: the fused verdict PLUS an analyst-committee report (bull case vs bear case argued by independent models, then synthesized) with key strengths, key risks, and a bottom line. Use for a thorough pre-investment deep-dive.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
    },
    async ({ chain, address }) => {
      const r = await tokenVerdictDeep(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_replay_sim",
    "Independently reproduce Aletheia's honeypot simulation at the exact fork block from a prior verdict's proof. Returns whether the same result is obtained — Aletheia's evidence is replayable and auditable, not a black-box score.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
      fork_block: z.string().describe("the forkBlock from the verdict's provenance/proof"),
    },
    async ({ chain, address, fork_block }) => {
      const r = await replaySim(chain as ChainKey, address as `0x${string}`, fork_block);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_courtroom",
    "The Aletheia Courtroom: a Prosecutor agent and a Defense agent argue a token from the same on-chain evidence, then Aletheia presides and delivers a ruling and one-line sentence. A vivid, shareable, evidence-grounded pre-trade assessment.",
    { chain: z.enum(CHAIN_KEYS), address: z.string().regex(/^0x[a-fA-F0-9]{40}$/) },
    async ({ chain, address }) => {
      const r = await tokenVerdictCourtroom(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_firewall_check",
    "Pre-signing transaction firewall for agents: decode a proposed transaction (native transfer, ERC-20 approve/transfer, or contract call) and return ALLOW / WARN / BLOCK with reasons. Checks the recipient/spender for malicious flags, unlimited approvals, and runs a full token verdict on the target. Call this BEFORE signing any transaction.",
    {
      chain: z.enum(CHAIN_KEYS),
      to: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("transaction target address"),
      data: z.string().optional().describe("calldata hex (0x…), if any"),
      value: z.string().optional().describe("native value in wei (decimal or 0x hex)"),
    },
    async ({ chain, to, data, value }) => {
      const r = await evaluateTx(chain as ChainKey, { to, data, value });
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_wallet_pnl",
    "Score a wallet's real trading track record: fee-adjusted realized PnL (native units), win-rate, trade count and per-token breakdown — reconstructed from on-chain history via FIFO cost-basis. Use to judge whether a wallet is smart money worth copying, or to vet a token's top buyers.",
    {
      chain: z.enum(CHAIN_KEYS).describe("EVM chain"),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("wallet address to score"),
    },
    async ({ chain, address }) => {
      const r = await walletPnl(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_airdrop_sybil_check",
    "Score a wallet's airdrop sybil-farming footprint: whether it shares a funding hub with many other fresh wallets, how thin its organic activity is, and how new it is. Returns LIKELY_SYBIL / MIXED / LIKELY_ORGANIC with reasons. Use to filter farmers from real users in an airdrop.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("wallet to assess"),
    },
    async ({ chain, address }) => {
      const r = await airdropSybilCheck(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_tax_report",
    "Generate a realized gain/loss tax report for a wallet: FIFO cost-basis per disposal, short vs long-term classification, total proceeds/cost/gain — reconstructed from on-chain trade history. Denominated in the chain's native asset. Optionally filter by tax year.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("wallet to report on"),
      year: z.number().int().optional().describe("filter disposals to this calendar year (UTC)"),
    },
    async ({ chain, address, year }) => {
      const r = await taxReport(chain as ChainKey, address, { year });
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_copy_intel",
    "Grade a wallet's copyworthiness for copy-trading: a SMART_MONEY/DECENT/UNPROVEN/UNDERWATER label + score from its fee-adjusted realized PnL and win-rate (gated on a real sample), plus its current open positions (what it's holding now). Use to decide whether to mirror a wallet.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("wallet to grade for copying"),
    },
    async ({ chain, address }) => {
      const r = await copyIntel(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_guardian_scan",
    "Scan a wallet's live ERC-20 token approvals and return a prioritized revoke list: which spenders can still move the wallet's tokens, which allowances are unlimited, and which spenders are flagged malicious. Use to audit and clean up a wallet's approval exposure.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe("wallet to audit"),
    },
    async ({ chain, address }) => {
      const r = await guardWallet(chain as ChainKey, address);
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_resolve_outcome",
    "Measure a token's REAL outcome now — rugged, honeypot-flipped, degraded, or survived — from current liquidity (vs an optional baseline captured at verdict time) plus a fresh honeypot re-simulation. This is how Aletheia grades its own past verdicts; use to audit whether a prior call was right.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
      baseline_liquidity_usd: z.number().optional().describe("liquidity (USD) at the time of the original verdict, for a precise rug-drop measurement"),
    },
    async ({ chain, address, baseline_liquidity_usd }) => {
      const r = await resolveOutcome(chain as ChainKey, address, { baselineLiquidityUsd: baseline_liquidity_usd ?? null });
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    }
  );

  server.tool(
    "aletheia_watch_check",
    "Monitoring check for a watched token: returns the current risk snapshot and, if a previous snapshot is supplied, any REASONED alerts about material changes (verdict downgrade, a newly-appeared critical flag / honeypot flip, a liquidity pull). Store the returned snapshot and pass it back next time.",
    {
      chain: z.enum(CHAIN_KEYS),
      address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
      previous_snapshot: z.any().optional().describe("the snapshot returned by the previous call, to diff against"),
    },
    async ({ chain, address, previous_snapshot }) => {
      const { snap } = await snapshotOf(chain as ChainKey, address);
      const alerts = previous_snapshot ? diffSnapshots(previous_snapshot as Snapshot, snap) : [];
      return { content: [{ type: "text", text: JSON.stringify({ snapshot: snap, alerts }, null, 2) }] };
    }
  );

  return server;
}

async function main() {
  const server = buildMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr so we don't corrupt the stdio JSON-RPC channel
  console.error("Aletheia MCP server running on stdio");
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").pop()!);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
