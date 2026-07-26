import { createHash } from "node:crypto";
import { chat } from "../ai/router.js";
import { EvidenceProof, type Extraction } from "./types.js";
import { safeFetch, SsrfError } from "../net/safeFetch.js";

/** Extract the first balanced JSON object from arbitrary model text. */
function parseJsonObject(s: string): any | undefined {
  const t = s.trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
  try { return JSON.parse(t); } catch { /* find embedded */ }
  const start = t.indexOf("{");
  if (start < 0) return undefined;
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < t.length; i++) {
    const c = t[i]!;
    if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}") { if (--depth === 0) { try { return JSON.parse(t.slice(start, i + 1)); } catch { return undefined; } } }
  }
  return undefined;
}

/**
 * Prove a claim against a live URL: fetch → hash the exact bytes → extract the answer (no fabrication) →
 * ground the snippet against the fetched content. Everything an agent needs to trust a fact before acting.
 */

const MAX_BYTES = 2_000_000; // cap fetched content
const MAX_TEXT_CHARS = 14_000; // cap what we send to the extractor

/** Strip HTML to readable text (cheap; good enough to locate a fact). Keeps the raw bytes for hashing. */
export function htmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

/** Normalize whitespace for a tolerant "is this snippet in the content" check (models re-space quotes). */
export function includesLoose(haystack: string, needle: string): boolean {
  if (!needle) return false;
  const norm = (s: string) => s.toLowerCase().replace(/\s+/g, " ").trim();
  return norm(haystack).includes(norm(needle));
}

export async function proveFact(url: string, query: string, opts: { timeoutMs?: number } = {}): Promise<EvidenceProof> {
  const fetched_at = new Date().toISOString();
  const base = {
    ok: false, url, query, fetched_at,
    http: { status: null as number | null, content_type: null as string | null, content_length: 0 },
    content_sha256: null as string | null,
    extraction: null as Extraction | null,
    attestation: null,
    replay: `Re-fetch ${url} and sha256 the body; compare to content_sha256 (snapshot at ${fetched_at}).`,
    disclaimer: "Snapshot proof of content served at fetched_at. Dynamic pages may differ on re-fetch.",
  };
  if (!/^https?:\/\//i.test(url)) return EvidenceProof.parse({ ...base, error: "url must be http(s)" });

  let raw = "";
  let status: number | null = null, contentType: string | null = null, bytes = 0;
  try {
    // SSRF-guarded: blocks loopback/private/link-local/metadata targets and re-validates redirects.
    const r = await safeFetch(url, { maxBytes: MAX_BYTES, timeoutMs: opts.timeoutMs ?? 25_000, accept: "text/html,application/json,text/plain,*/*" });
    status = r.status; contentType = r.contentType; bytes = r.bytes; raw = r.text;
  } catch (e: any) {
    return EvidenceProof.parse({ ...base, http: { status, content_type: contentType, content_length: bytes }, error: e instanceof SsrfError ? `blocked: ${e.message}` : e?.name === "AbortError" ? "fetch timeout" : e?.message ?? String(e) });
  }

  const content_sha256 = createHash("sha256").update(raw).digest("hex");
  const text = (contentType && /json|plain/.test(contentType) ? raw : htmlToText(raw)).slice(0, MAX_TEXT_CHARS);

  // extract the answer — strictly grounded, no fabrication; on 0G decentralized compute
  let extraction: Extraction;
  let attestation: { tee_verified: boolean; provider?: string; model?: string } | null = null;
  try {
    const r = await chat(
      [
        { role: "system", content: "You extract a factual answer from web page content. Use ONLY the provided content — never invent or infer beyond it. Return ONLY JSON {\"found\": boolean, \"value\": string|null, \"snippet\": string|null}. 'snippet' MUST be an exact verbatim substring copied from the content that contains the answer. If the content does not contain the answer, return found=false with null value and snippet." },
        { role: "user", content: `QUESTION: ${query}\n\nCONTENT:\n${text}` },
      ],
      { tier: "strong", maxTokens: 300, temperature: 0, verifyTee: true }
    );
    attestation = { tee_verified: r.teeVerified === true, provider: r.provider, model: r.model };
    const data = parseJsonObject(r.content) ?? {};
    const snippet_verified = !!(data.snippet && includesLoose(text, String(data.snippet)));
    const found = !!data.found && data.value != null;
    extraction = {
      found,
      value: data.value != null ? String(data.value) : null,
      snippet: data.snippet != null ? String(data.snippet) : null,
      snippet_verified,
      // grounded (snippet present verbatim) → high; found but ungrounded → capped low
      confidence: found ? (snippet_verified ? 0.9 : 0.4) : 0.6,
    };
  } catch {
    extraction = { found: false, value: null, snippet: null, snippet_verified: false, confidence: 0.2 };
  }

  return EvidenceProof.parse({
    ...base, ok: true,
    http: { status, content_type: contentType, content_length: bytes },
    content_sha256, extraction, attestation,
  });
}
