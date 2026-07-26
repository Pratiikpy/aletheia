/**
 * Keyless web-evidence retrieval for Settle It — no API key required.
 *
 * Search: DuckDuckGo HTML endpoint (titles + real URLs + snippets in one request).
 * Read:   Jina Reader (r.jina.ai) turns any page into clean markdown for deeper grounding.
 *
 * Everything a grounded ruling needs: real, citable sources fetched at decision time, so the verdict
 * rests on evidence a human or agent can open and check — not the model's memory.
 */

export type Source = { id: number; title: string; url: string; snippet: string; content?: string };

const UA = "Mozilla/5.0 (compatible; AletheiaEvidence/1.0)";

function decodeDdgUrl(href: string): string {
  // DDG wraps results as /l/?uddg=<encoded target>&rut=...
  const m = href.match(/[?&]uddg=([^&]+)/);
  if (m) { try { return decodeURIComponent(m[1]!); } catch { /* fall through */ } }
  if (href.startsWith("//")) return "https:" + href;
  return href;
}

function stripTags(s: string): string {
  return s.replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#x27;|&#39;/g, "'").replace(/\s+/g, " ").trim();
}

function pushResult(out: Source[], seen: Set<string>, url: string, title: string, snippet: string, limit: number): void {
  if (out.length >= limit || !/^https?:\/\//.test(url) || !title) return;
  const host = (() => { try { return new URL(url).host.replace(/^www\./, ""); } catch { return url; } })();
  if (seen.has(host) || /duckduckgo\.com$/.test(host)) return; // one per domain; drop DDG chrome links
  seen.add(host);
  out.push({ id: out.length + 1, title: title.slice(0, 160), url, snippet: snippet.slice(0, 400) });
}

/** DuckDuckGo search, fetched THROUGH Jina Reader (keyless + not blocked from datacenter IPs).
 *  Falls back to a direct DDG HTML scrape if Jina is unavailable. Returns title/url/snippet. */
export async function searchWeb(query: string, limit = 5, timeoutMs = 20_000): Promise<Source[]> {
  const ddg = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
  const out: Source[] = [];
  const seen = new Set<string>();

  // primary: Jina reads the DDG results page → markdown "## [title](ddg-redirect)" + snippet text
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`https://r.jina.ai/${ddg}`, { headers: { "User-Agent": UA, "X-Return-Format": "markdown" }, signal: controller.signal });
    if (res.ok) {
      const md = await res.text();
      const re = /##\s*\[([^\]]+)\]\((https?:\/\/[^)]+)\)([\s\S]*?)(?=\n##\s*\[|$)/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(md)) && out.length < limit) {
        const url = decodeDdgUrl(m[2]!);
        const title = stripTags(m[1]!);
        const snippet = m[3]!.replace(/!?\[[^\]]*\]\([^)]*\)/g, " ").replace(/[#>*_`]/g, " ").replace(/\s+/g, " ").trim();
        pushResult(out, seen, url, title, snippet, limit);
      }
    }
  } catch { /* fall through to direct */ } finally { clearTimeout(t); }
  if (out.length) return out;

  // fallback: direct DDG HTML scrape (may be rate-limited from datacenter IPs)
  const c2 = new AbortController();
  const t2 = setTimeout(() => c2.abort(), timeoutMs);
  try {
    const res = await fetch(ddg, { headers: { "User-Agent": UA, Accept: "text/html" }, signal: c2.signal });
    if (!res.ok) return out;
    const html = await res.text();
    const blockRe = /class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>([\s\S]*?)(?=class="result__a"|$)/g;
    let m: RegExpExecArray | null;
    while ((m = blockRe.exec(html)) && out.length < limit) {
      const snipM = m[3]!.match(/result__snippet"[^>]*>([\s\S]*?)<\/a>/);
      pushResult(out, seen, decodeDdgUrl(m[1]!), stripTags(m[2]!), snipM ? stripTags(snipM[1]!) : "", limit);
    }
    return out;
  } catch { return out; } finally { clearTimeout(t2); }
}

const CRAWL4AI_URL = process.env.CRAWL4AI_URL || "";
const CRAWL4AI_TOKEN = process.env.CRAWL4AI_TOKEN || "";

/** Read a page via self-hosted Crawl4AI (renders JavaScript → clean markdown) when available; falls
 *  back to Jina Reader (keyless). Crawl4AI handles JS-heavy / anti-bot pages Jina can't. */
async function crawl4aiRead(url: string, timeoutMs: number): Promise<string> {
  if (!CRAWL4AI_URL) return "";
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${CRAWL4AI_URL}/md`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(CRAWL4AI_TOKEN ? { Authorization: `Bearer ${CRAWL4AI_TOKEN}` } : {}) },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    if (!res.ok) return "";
    const j: any = await res.json().catch(() => null);
    return String(j?.markdown ?? "").replace(/\n{3,}/g, "\n\n");
  } catch { return ""; } finally { clearTimeout(t); }
}

async function jinaRead(url: string, timeoutMs: number): Promise<string> {
  // Jina's free tier rate-limits bursts from a shared datacenter IP with HTTP 429. A short bounded
  // backoff clears it far more often than a single shot — so retry a couple of times before giving up.
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 900 * attempt));
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`https://r.jina.ai/${url}`, { headers: { "User-Agent": UA, "X-Return-Format": "text" }, signal: controller.signal });
      if (res.status === 429) continue; // rate-limited — back off and retry
      if (!res.ok) return "";
      return (await res.text()).replace(/\n{3,}/g, "\n\n");
    } catch { /* transient — retry */ } finally { clearTimeout(t); }
  }
  return "";
}

/** Read a page as clean markdown — Crawl4AI (JS-rendered) first, then Jina Reader (with 429 backoff). Capped. */
export async function readPage(url: string, maxChars = 4000, timeoutMs = 20_000): Promise<string> {
  const md = (await crawl4aiRead(url, timeoutMs)) || (await jinaRead(url, timeoutMs));
  return md.slice(0, maxChars);
}

/**
 * Gather evidence for a dispute: search a couple of angles, dedupe by domain, and deep-read the top
 * sources so the jury argues over real content. Returns a numbered source list for [n] citations.
 */
export async function gatherEvidence(question: string, sideA?: string, sideB?: string, opts: { maxSources?: number; deepRead?: number } = {}): Promise<Source[]> {
  const maxSources = opts.maxSources ?? 5;
  const deepRead = opts.deepRead ?? 2;
  const queries = [question.slice(0, 200)];
  // a second angle from the sides sharpens retrieval when both positions are given
  if (sideA && sideB) queries.push(`${question.slice(0, 120)} ${sideA.slice(0, 40)} OR ${sideB.slice(0, 40)}`);

  const batches = await Promise.all(queries.map((q) => searchWeb(q, maxSources)));
  const merged: Source[] = [];
  const seen = new Set<string>();
  for (const batch of batches) for (const s of batch) {
    const host = (() => { try { return new URL(s.url).host.replace(/^www\./, ""); } catch { return s.url; } })();
    if (seen.has(host)) continue;
    seen.add(host); merged.push({ ...s, id: merged.length + 1 });
    if (merged.length >= maxSources) break;
  }
  // deep-read the top sources for richer grounding (best-effort; snippet is the fallback)
  await Promise.all(merged.slice(0, deepRead).map(async (s) => { const c = await readPage(s.url); if (c) s.content = c; }));
  return merged;
}

/** Compact, numbered evidence block for prompting; [n] maps to source id. */
export function evidenceBlock(sources: Source[]): string {
  if (!sources.length) return "(no external sources were retrievable; rule on reasoning and known facts, and say so)";
  return sources.map((s) => `[${s.id}] ${s.title} — ${s.url}\n${(s.content || s.snippet || "").slice(0, 900)}`).join("\n\n");
}
