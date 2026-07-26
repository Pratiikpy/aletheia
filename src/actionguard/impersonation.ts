import { promises as dns } from "node:dns";
import { exec } from "node:child_process";

/**
 * Brand-impersonation hunter — find live lookalikes of a brand before an agent trusts a link/handle.
 * Core signal is deterministic and high-value: generate typosquat domain variants of the official domain
 * and check which ones actually RESOLVE (a resolving lookalike is a real phishing candidate). Optional
 * social-handle scan via agent-reach. Honest coverage note: this is generative+resolve detection, not a
 * threat-intel feed — it catches typosquats, not every impersonation. Per-call ASP.
 */

export type ImpersonationResult = {
  ok: boolean;
  observed_at: string;
  brand: string;
  official_domain: string | null;
  variants_checked: number;
  live_lookalikes: { domain: string; ips: string[] }[]; // resolving typosquat domains
  suspicious_handles: string[]; // social handles worth reviewing
  verdict: "TYPOSQUATS_FOUND" | "CLEAR" | "UNAVAILABLE";
  summary: string;
  error?: string;
};

const HOMOGLYPHS: Record<string, string[]> = { o: ["0"], l: ["1", "i"], i: ["1", "l"], e: ["3"], a: ["4"], s: ["5"], b: ["8"] };
const ALT_TLDS = ["net", "org", "io", "co", "app", "xyz", "info", "co"];
const ADDONS = ["-app", "-official", "-wallet", "-login", "app", "secure"];

/** Generate typosquat variants of a domain (pure, testable). */
export function generateTyposquats(domain: string): string[] {
  const d = domain.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
  const dot = d.lastIndexOf(".");
  if (dot < 1) return [];
  const name = d.slice(0, dot), tld = d.slice(dot + 1);
  const out = new Set<string>();
  // omission + transposition only for longer names — on short brands they degrade into unrelated real domains
  if (name.length >= 5) {
    for (let i = 0; i < name.length; i++) out.add(name.slice(0, i) + name.slice(i + 1) + "." + tld); // omission
    for (let i = 0; i < name.length - 1; i++) out.add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2) + "." + tld); // transposition
  }
  // doubling
  for (let i = 0; i < name.length; i++) out.add(name.slice(0, i + 1) + name[i] + name.slice(i + 1) + "." + tld);
  // homoglyphs
  for (let i = 0; i < name.length; i++) for (const g of HOMOGLYPHS[name[i]!] ?? []) out.add(name.slice(0, i) + g + name.slice(i + 1) + "." + tld);
  // TLD swaps
  for (const t of ALT_TLDS) if (t !== tld) out.add(name + "." + t);
  // add-ons + hyphenation
  for (const a of ADDONS) { out.add(name + a + "." + tld); out.add(a.replace(/^-/, "") + "-" + name + "." + tld); }
  out.delete(d);
  return [...out].slice(0, 40);
}

async function resolves(domain: string): Promise<string[] | null> {
  try {
    const ips = await Promise.race([
      dns.resolve4(domain),
      new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error("t")), 4000)),
    ]);
    return ips.length ? ips : null;
  } catch { return null; }
}

async function twitterHandles(brand: string): Promise<string[]> {
  return new Promise((resolve) => {
    const q = brand.replace(/["`$;|&<>\\]/g, " ").slice(0, 40);
    exec(`twitter search "${q}" -n 15 --json`, { timeout: 30000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (_e, stdout) => {
      try {
        const data: any[] = JSON.parse(stdout).data ?? [];
        const handles = new Set<string>();
        for (const t of data) { const h = t.author?.screenName; if (h && new RegExp(brand.replace(/\s/g, ""), "i").test(h) && !t.author?.verified) handles.add("@" + h); }
        resolve([...handles].slice(0, 8));
      } catch { resolve([]); }
    });
  });
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx]!); } }));
  return out;
}

export async function huntImpersonation(brand: string, officialDomain?: string): Promise<ImpersonationResult> {
  const observed_at = new Date().toISOString();
  const variants = officialDomain ? generateTyposquats(officialDomain) : [];
  try {
    const [resolvedRows, handles] = await Promise.all([
      mapLimit(variants, 8, async (v) => ({ domain: v, ips: await resolves(v) })),
      twitterHandles(brand).catch(() => []),
    ]);
    const live_lookalikes = resolvedRows.filter((r) => r.ips).map((r) => ({ domain: r.domain, ips: r.ips as string[] }));
    const found = live_lookalikes.length > 0 || handles.length > 0;
    return {
      ok: true, observed_at, brand, official_domain: officialDomain ?? null,
      variants_checked: variants.length, live_lookalikes, suspicious_handles: handles,
      verdict: found ? "TYPOSQUATS_FOUND" : "CLEAR",
      summary: found
        ? `${live_lookalikes.length} resolving typosquat domain(s)${handles.length ? ` and ${handles.length} similar handle(s)` : ""} to REVIEW — a resolving lookalike is a phishing candidate, not confirmed malicious. Verify against the official domain before trusting.`
        : `No resolving typosquat domains or similar handles found${officialDomain ? "" : " (supply the official domain for domain scanning)"}.`,
    };
  } catch (e: any) {
    return { ok: false, observed_at, brand, official_domain: officialDomain ?? null, variants_checked: variants.length, live_lookalikes: [], suspicious_handles: [], verdict: "UNAVAILABLE", summary: "Impersonation scan failed.", error: e?.message ?? String(e) };
  }
}
