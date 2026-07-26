import { z } from "zod";

/**
 * THE VERITY VERDICT ENVELOPE — single source of truth.
 * Every module (risk, intel, monitoring, reports) emits this shape.
 * Design rules (audit-proven):
 *  - verdict + score + confidence ALWAYS present.
 *  - every signal carries severity + confidence + evidence[] (no claim without evidence).
 *  - a hard security red flag caps the composite regardless of other dimensions.
 *  - low confidence downgrades the verdict (never a confident GO on thin data).
 *  - provenance labels how each value was obtained (SIMULATED/CACHED/SAMPLED + counts).
 *  - cost is echoed so the calling agent can do budget math.
 */

export const VerdictLabel = z.enum(["GO", "CAUTION", "AVOID"]);
export type VerdictLabel = z.infer<typeof VerdictLabel>;

export const DimensionKey = z.enum([
  "security",
  "market_structure",
  "smart_money",
  "tokenomics",
  "social_narrative",
  "research",
]);
export type DimensionKey = z.infer<typeof DimensionKey>;

/** One piece of proof backing a signal. Either an on-chain/sim observation or a cited source. */
export const Evidence = z.object({
  source: z.string(), // e.g. "multi_vector_sim" | "goplus" | "okx_onchainos" | "contract" | "rpc"
  method: z.string().optional(), // e.g. "holder_replay" | "eth_call" | "api"
  detail: z.string().optional(), // human-readable specifics
  url: z.string().url().optional(), // explorer / source link when applicable
  snippet: z.string().optional(), // exact quoted value/code when applicable
  observed_at: z.string(), // ISO timestamp — freshness of THIS observation
});
export type Evidence = z.infer<typeof Evidence>;

export const Signal = z.object({
  code: z.string(), // machine code, e.g. "selective_honeypot", "fake_renounce", "unbounded_modifiable_tax"
  severity: z.number().int().min(1).max(5), // 1 = minor, 5 = critical
  finding: z.string(), // plain-English what-this-means
  confidence: z.number().min(0).max(1),
  dimension: DimensionKey,
  is_hard_flag: z.boolean().default(false), // if true, caps the composite verdict
  evidence: z.array(Evidence).min(1), // NEVER empty — no claim without evidence
});
export type Signal = z.infer<typeof Signal>;

export const DimensionResult = z.object({
  verdict: VerdictLabel,
  score: z.number().min(0).max(100),
  weight: z.number().min(0).max(1),
  confidence: z.number().min(0).max(1),
  summary: z.string().optional(),
});
export type DimensionResult = z.infer<typeof DimensionResult>;

export const Subject = z.object({
  type: z.enum(["token", "wallet", "contract"]),
  chain: z.string(), // "xlayer" | "ethereum" | "bsc" | "base" | "solana" | ...
  address: z.string(),
  symbol: z.string().optional(),
  name: z.string().optional(),
});
export type Subject = z.infer<typeof Subject>;

export const Provenance = z.object({
  simulation: z.enum(["MULTI_VECTOR", "SINGLE", "NONE"]).optional(),
  sizes_tested: z.number().int().optional(),
  origins_tested: z.number().int().optional(),
  holders_sampled: z.number().int().optional(),
  liquidity: z.enum(["REAL", "SIMULATED", "NONE"]).optional(),
  cached_dimensions: z.array(DimensionKey).optional(),
  replay: z.string().optional(), // command to independently reproduce the honeypot simulation
  fork_block: z.string().optional(),
});
export type Provenance = z.infer<typeof Provenance>;

export const Cost = z.object({
  amount: z.string(), // stringified decimal to avoid float drift
  currency: z.enum(["USDT", "USDG"]),
  tier: z.enum(["flag", "full", "deep"]),
});
export type Cost = z.infer<typeof Cost>;

export const AccuracyContext = z.object({
  model_version: z.string(),
  published_precision: z.number().min(0).max(1).nullable(),
  scoreboard_url: z.string().optional(),
});
export type AccuracyContext = z.infer<typeof AccuracyContext>;

/** Live OKX Onchain OS metrics surfaced on the verdict (present only when OKX API creds are configured). */
export const OkxMetrics = z.object({
  smart_money_signals: z.number().int().nullable(),
  cluster_concentration: z.string().nullable(), // "Low" | "Medium" | "High"
  rug_pull_percent: z.number().nullable(), // 0..1
  same_fund_source_percent: z.number().nullable(), // 0..1 — holders sharing a funding wallet
  dev_holding_percent: z.number().nullable(), // 0..1
  bundle_holding_percent: z.number().nullable(), // 0..1 — supply bought in bundled launch txns
});
export type OkxMetrics = z.infer<typeof OkxMetrics>;

/** AI attestation from 0G. `tee_verified` is true ONLY when the provider returns a verified TEE
 *  attestation; on the standard 0G router path it is false (no per-call TEE), so treat it as
 *  best-effort provenance, not a guarantee of un-manipulated execution. */
export const AiAttestation = z.object({
  tee_verified: z.boolean(),
  provider: z.string().optional(),
  model: z.string().optional(),
});
export type AiAttestation = z.infer<typeof AiAttestation>;

export const Verdict = z.object({
  subject: Subject,
  verdict: VerdictLabel,
  score: z.number().min(0).max(100),
  confidence: z.number().min(0).max(1),
  summary: z.string(),
  dimensions: z.record(z.string(), DimensionResult), // partial: only present dimensions included
  signals: z.array(Signal),
  freshness: z.record(z.string(), z.string()), // dimension -> ISO timestamp
  provenance: Provenance,
  cost: Cost,
  accuracy: AccuracyContext,
  ai_attestation: AiAttestation.nullable().optional(),
  okx_metrics: OkxMetrics.nullable().optional(), // live OKX Onchain OS data (null unless OKX creds configured)
  generated_at: z.string(),
  latency_ms: z.number().int().optional(),
  disclaimer: z.string().default("Informational only. Not financial advice."),
});
export type Verdict = z.infer<typeof Verdict>;

/** What a dimension scorer returns to the fusion engine. */
export type DimensionScore = {
  key: DimensionKey;
  verdict: VerdictLabel;
  score: number; // 0-100
  confidence: number; // 0-1
  signals: Signal[];
  freshness: string; // ISO
  summary?: string;
};
