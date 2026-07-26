import { z } from "zod";

export const PulseLabel = z.enum(["HYPE", "ORGANIC", "DEAD"]);
export type PulseLabel = z.infer<typeof PulseLabel>;

export const PulseSource = z.object({
  source: z.enum(["twitter", "reddit", "youtube"]),
  status: z.enum(["ok", "empty", "error"]),
  count: z.number().int(),
  engagement: z.number(),
  message: z.string(),
});

export const PulseVerdict = z.object({
  ok: z.boolean(),
  query: z.string(),
  observed_at: z.string(),
  label: PulseLabel, // HYPE = loud+promotional, ORGANIC = genuine discussion, DEAD = little/no chatter
  sentiment: z.enum(["bullish", "neutral", "bearish", "mixed"]),
  buzz_score: z.number().min(0).max(100), // volume × engagement, 0..100
  confidence: z.number().min(0).max(1), // scales with how many sources responded
  rationale: z.string(),
  red_flags: z.array(z.string()), // e.g. coordinated shilling, bot-like repetition
  sources: z.array(PulseSource),
  total_mentions: z.number().int(),
  sources_ok: z.number().int(),
  sample: z.array(z.object({ source: z.string(), text: z.string(), engagement: z.number(), url: z.string().optional() })),
  attestation: z.object({ tee_verified: z.boolean(), provider: z.string().optional(), model: z.string().optional() }).nullable().optional(),
  disclaimer: z.string().default("Social signal only. Chatter is not price prediction; hype is often a sell signal."),
  error: z.string().optional(),
});
export type PulseVerdict = z.infer<typeof PulseVerdict>;
