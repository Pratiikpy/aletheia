import { chat } from "../ai/router.js";
import { htmlToText } from "../evidence/prove.js";
import { safeFetch, SsrfError } from "../net/safeFetch.js";

/**
 * Contract / Invoice Risk Reviewer — a document in (raw text or a URL), a risk read out: dangerous
 * clauses, missing protections, unusual terms, and a LOW / MEDIUM / HIGH risk verdict.
 * Per-call ASP, no data moat. Off the crypto thesis but a clean, high-willingness-to-pay surface.
 */

export type DocReview = {
  ok: boolean;
  observed_at: string;
  doc_type: string; // e.g. "contract", "invoice", "terms", "unknown"
  verdict: "LOW" | "MEDIUM" | "HIGH";
  risk_flags: { severity: "low" | "medium" | "high"; issue: string; where: string }[];
  missing_protections: string[];
  key_terms: string[];
  summary: string;
  attestation: { tee_verified: boolean; provider?: string; model?: string } | null;
  chars_reviewed: number;
  error?: string;
};

function parseJson(s: string): any | undefined {
  const t = (s || "").trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
  try { return JSON.parse(t); } catch {}
  const a = t.indexOf("{"), b = t.lastIndexOf("}");
  if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch {} }
  return undefined;
}

const norm = (v: any): "LOW" | "MEDIUM" | "HIGH" => {
  const s = String(v || "").toUpperCase();
  return s === "HIGH" || s === "MEDIUM" || s === "LOW" ? (s as any) : "MEDIUM";
};

export async function reviewDoc(input: { text?: string; url?: string }): Promise<DocReview> {
  const observed_at = new Date().toISOString();
  const base = { ok: false, observed_at, doc_type: "unknown", verdict: "MEDIUM" as const, risk_flags: [], missing_protections: [], key_terms: [], attestation: null, chars_reviewed: 0 };

  let text = input.text ?? "";
  if (!text && input.url) {
    if (!/^https?:\/\//i.test(input.url)) return { ...base, summary: "", error: "url must be http(s)" };
    try {
      // SSRF-guarded fetch (blocks internal/metadata targets, caps size, re-validates redirects).
      const r = await safeFetch(input.url, { maxBytes: 2_000_000, timeoutMs: 20_000 });
      text = /json|plain/.test(r.contentType || "") ? r.text : htmlToText(r.text);
    } catch (e: any) {
      return { ...base, summary: "", error: e instanceof SsrfError ? `blocked: ${e.message}` : `fetch failed: ${e?.message ?? e}` };
    }
  }
  text = text.trim().slice(0, 16_000);
  if (text.length < 40) return { ...base, summary: "", error: "document too short or empty" };

  try {
    const r = await chat(
      [
        { role: "system", content: "You are a contract/invoice risk reviewer. Analyze the document and return ONLY JSON: {\"doc_type\": string, \"verdict\": \"LOW\"|\"MEDIUM\"|\"HIGH\", \"risk_flags\": [{\"severity\":\"low\"|\"medium\"|\"high\",\"issue\":string,\"where\":short quote/section}], \"missing_protections\": [string], \"key_terms\": [string]}. Focus on dangerous clauses (auto-renewal, unlimited liability, one-sided termination, hidden fees, IP assignment, unusual penalties), missing standard protections, and unusual terms. Use ONLY the document text. Keep each string short." },
        { role: "user", content: `DOCUMENT:\n${text}` },
      ],
      { tier: "strong", maxTokens: 700, temperature: 0.15, verifyTee: true }
    );
    const d = parseJson(r.content) ?? {};
    const risk_flags = Array.isArray(d.risk_flags) ? d.risk_flags.slice(0, 10).map((f: any) => ({
      severity: (["low", "medium", "high"].includes(String(f.severity).toLowerCase()) ? String(f.severity).toLowerCase() : "medium") as any,
      issue: String(f.issue ?? "").slice(0, 200), where: String(f.where ?? "").slice(0, 120),
    })).filter((f: any) => f.issue) : [];
    const verdict = norm(d.verdict);
    const highs = risk_flags.filter((f: any) => f.severity === "high").length;
    return {
      ...base, ok: true,
      doc_type: String(d.doc_type ?? "unknown").slice(0, 40),
      verdict,
      risk_flags,
      missing_protections: Array.isArray(d.missing_protections) ? d.missing_protections.slice(0, 8).map((s: any) => String(s).slice(0, 160)) : [],
      key_terms: Array.isArray(d.key_terms) ? d.key_terms.slice(0, 10).map((s: any) => String(s).slice(0, 120)) : [],
      summary: `${verdict} risk — ${risk_flags.length} flag(s)${highs ? ` (${highs} high-severity)` : ""} across a ${String(d.doc_type ?? "document")}.`,
      attestation: { tee_verified: r.teeVerified === true, provider: r.provider, model: r.model },
      chars_reviewed: text.length,
    };
  } catch (e: any) {
    return { ...base, summary: "", error: e?.message ?? String(e) };
  }
}
