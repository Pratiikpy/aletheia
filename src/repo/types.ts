import { z } from "zod";

/** RepoRadar — GitHub due-diligence verdict: is a repo real work, a shell, or a scam signal? */

export const RepoGrade = z.enum(["LEGIT", "COSMETIC", "RED_FLAG"]);
export type RepoGrade = z.infer<typeof RepoGrade>;

/** The cheap, gh-API-derived signals (no cloning / no compiler — that's a premium tier). */
export const RepoSignals = z.object({
  fullName: z.string(),
  stars: z.number().int(),
  forks: z.number().int(),
  ageDays: z.number(),
  lastPushDays: z.number(), // staleness
  contributors: z.number().int(), // capped sample
  topContributorShare: z.number(), // 0..1 — bus factor (1 = one person did everything)
  commitsSampled: z.number().int(),
  distinctAuthors: z.number().int(),
  commitSpanDays: z.number(), // time between first & last sampled commit
  openIssues: z.number().int(),
  isFork: z.boolean(),
  isArchived: z.boolean(),
  hasTests: z.boolean(),
  hasCI: z.boolean(),
  hasLicense: z.boolean(),
  hasReadme: z.boolean(),
  readmeLength: z.number().int(),
  starsPerContributor: z.number(),
  starsPerDay: z.number(),
});
export type RepoSignals = z.infer<typeof RepoSignals>;

export const RepoRadarReport = z.object({
  ok: z.boolean(),
  repo: z.string(),
  observed_at: z.string(),
  grade: RepoGrade,
  score: z.number().min(0).max(100),
  confidence: z.number().min(0).max(1),
  summary: z.string(),
  reasons: z.array(z.object({ severity: z.number().int().min(1).max(5), code: z.string(), detail: z.string() })),
  signals: RepoSignals.nullable(),
  claims_check: z.string().nullable(), // 0G read of README claims vs apparent code
  attestation: z.object({ tee_verified: z.boolean(), provider: z.string().optional(), model: z.string().optional() }).nullable().optional(),
  disclaimer: z.string().default("Metadata due-diligence only. Not a code audit; deep static analysis is a separate tier."),
  error: z.string().optional(),
});
export type RepoRadarReport = z.infer<typeof RepoRadarReport>;
