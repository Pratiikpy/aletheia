import { z } from "zod";

/**
 * Verified-evidence proof — the attested answer to "is this claim true at this URL, right now?".
 *
 * A per-call primitive for agents that must ground a claim in a real source before acting on it. Aletheia
 * fetches the URL, hashes the exact bytes served (a timestamped snapshot proof), then extracts the answer
 * with a no-fabrication model and GROUNDS it: the returned snippet must be an exact substring of the
 * fetched content, so the extraction can't be hallucinated. The reasoning runs in a 0G TEE (attested).
 */

export const Extraction = z.object({
  found: z.boolean(), // was the answer present in the fetched content?
  value: z.string().nullable(), // the extracted answer
  snippet: z.string().nullable(), // exact quoted text the value came from
  snippet_verified: z.boolean(), // true = snippet is a verbatim substring of the fetched content (grounded)
  confidence: z.number().min(0).max(1),
});
export type Extraction = z.infer<typeof Extraction>;

export const AiAttestation = z.object({
  tee_verified: z.boolean(),
  provider: z.string().optional(),
  model: z.string().optional(),
});

export const EvidenceProof = z.object({
  ok: z.boolean(),
  url: z.string(),
  query: z.string(),
  fetched_at: z.string(), // ISO timestamp of the snapshot
  http: z.object({
    status: z.number().int().nullable(),
    content_type: z.string().nullable(),
    content_length: z.number().int(), // bytes fetched
  }),
  content_sha256: z.string().nullable(), // hash of the exact bytes served — the snapshot fingerprint
  extraction: Extraction.nullable(),
  attestation: AiAttestation.nullable().optional(),
  replay: z.string(), // how to independently verify the snapshot hash
  disclaimer: z.string().default("Snapshot proof of content served at fetched_at. Dynamic pages may differ on re-fetch."),
  error: z.string().optional(),
});
export type EvidenceProof = z.infer<typeof EvidenceProof>;
