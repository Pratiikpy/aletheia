import { z } from "zod";

/** AgentAudit report envelope — the signed, evidence-linked trust scorecard for an agent/ASP. */

export const AuditGrade = z.enum(["GO", "CAUTION", "AVOID"]);
export type AuditGrade = z.infer<typeof AuditGrade>;

export const ProbeStatus = z.enum(["PASS", "WARN", "FAIL", "ERROR"]); // deepchecks four-state
export type ProbeStatus = z.infer<typeof ProbeStatus>;

export const ProbeResult = z.object({
  id: z.string(),
  dimension: z.enum(["injection_resistance", "accuracy", "latency", "cost"]),
  category: z.string(),
  status: ProbeStatus,
  weight: z.number(),
  hard: z.boolean().default(false),
  detail: z.string(),
  evidence: z.string(),
  latency_ms: z.number().int().nullable().optional(),
});
export type ProbeResult = z.infer<typeof ProbeResult>;

export const DimensionScore = z.object({
  score: z.number().min(0).max(100).nullable(), // null = not measurable
  verdict: AuditGrade.nullable(),
  confidence: z.number().min(0).max(1),
  passed: z.number().int(),
  failed: z.number().int(),
  errored: z.number().int(),
  summary: z.string(),
});
export type DimensionScore = z.infer<typeof DimensionScore>;

export const LatencyMetrics = z.object({
  calls: z.number().int(),
  errorRate: z.number(),
  p50_ms: z.number(),
  p95_ms: z.number(),
  p99_ms: z.number(),
  normalized_p95_ms_per_1k: z.number().nullable(), // latency per 1k output tokens (fairness-adjusted)
  avg_completion_tokens: z.number().nullable(),
});
export type LatencyMetrics = z.infer<typeof LatencyMetrics>;

export const CostMetrics = z.object({
  measurable: z.boolean(),
  avg_prompt_tokens: z.number().nullable(),
  avg_completion_tokens: z.number().nullable(),
  est_cost_per_call_usd: z.number().nullable(),
  note: z.string(),
});
export type CostMetrics = z.infer<typeof CostMetrics>;

export const AiAttestation = z.object({
  tee_verified: z.boolean(),
  provider: z.string().optional(),
  model: z.string().optional(),
});

export const AuditReport = z.object({
  subject: z.object({ type: z.literal("agent"), endpoint: z.string(), model: z.string() }),
  grade: AuditGrade,
  score: z.number().min(0).max(100),
  confidence: z.number().min(0).max(1),
  summary: z.string(),
  dimensions: z.object({
    injection_resistance: DimensionScore,
    accuracy: DimensionScore,
    latency: DimensionScore,
    cost: DimensionScore,
  }),
  metrics: z.object({ latency: LatencyMetrics, cost: CostMetrics }),
  probes: z.array(ProbeResult),
  ai_attestation: AiAttestation.nullable().optional(),
  provenance: z.object({ probes_run: z.number().int(), canary_used: z.boolean() }),
  cost: z.object({ amount: z.string(), currency: z.enum(["USDT", "USDG"]), tier: z.string() }),
  generated_at: z.string(),
  latency_ms: z.number().int().optional(),
  disclaimer: z.string().default("Informational only. Not a security guarantee."),
});
export type AuditReport = z.infer<typeof AuditReport>;
