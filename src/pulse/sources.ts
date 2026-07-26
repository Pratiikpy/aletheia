import { exec } from "node:child_process";
import { Scraper, SearchMode } from "@the-convocation/twitter-scraper";

/**
 * Social Pulse fetch layer — pulls recent mentions of a topic from Twitter, Reddit, and YouTube.
 *
 * Runs entirely over HTTP so it works inside the server container with no CLIs to install:
 *   - Twitter: authenticated reads via @the-convocation/twitter-scraper using session cookies
 *     (TWITTER_AUTH_TOKEN + TWITTER_CT0 from env). Twitter fights datacenter IPs, so this can be
 *     rate-limited/challenged from a cloud host — it degrades to "error" and the verdict carries on.
 *   - Reddit: public search JSON (optionally authenticated with REDDIT_COOKIE for higher limits).
 *   - YouTube: yt-dlp if present (best-effort; absent → clean "error", never blocks the others).
 *
 * Each source is probed independently and returns a health status (ok / empty / error), so the
 * verdict degrades gracefully to whatever responded and honestly flags the gaps.
 */

export type Mention = {
  source: "twitter" | "reddit" | "youtube";
  text: string;
  engagement: number; // source-normalized interaction count
  url?: string;
};

export type SourceResult = {
  source: "twitter" | "reddit" | "youtube";
  status: "ok" | "empty" | "error";
  mentions: Mention[];
  message: string;
};

/** Sanitize a query for safe shell interpolation (YouTube CLI path only). */
function safeQuery(q: string): string {
  return q.replace(/["`$;|&<>\\]/g, " ").replace(/\s+/g, " ").trim().slice(0, 80);
}

function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => T): Promise<T> {
  return Promise.race([p, new Promise<T>((res) => setTimeout(() => res(onTimeout()), ms))]);
}

// ---------- Twitter (authenticated cookie session, lazily initialized once) ----------
let scraperPromise: Promise<Scraper | null> | null = null;
let scraperError = "";

export async function getScraper(): Promise<Scraper | null> {
  const authToken = process.env.TWITTER_AUTH_TOKEN;
  const ct0 = process.env.TWITTER_CT0;
  if (!authToken || !ct0) { scraperError = "TWITTER_AUTH_TOKEN/TWITTER_CT0 unset"; return null; }
  if (!scraperPromise) {
    scraperPromise = (async () => {
      const s = new Scraper();
      // Pass full cookie strings (with Domain) for both twitter.com and x.com — the scraper parses
      // them with its own tough-cookie and may route to either host depending on version.
      const cookies = [".twitter.com", ".x.com"].flatMap((d) => [
        `auth_token=${authToken}; Domain=${d}; Path=/; Secure; HttpOnly`,
        `ct0=${ct0}; Domain=${d}; Path=/; Secure`,
      ]);
      await s.setCookies(cookies);
      const loggedIn = await s.isLoggedIn().catch(() => false);
      scraperError = loggedIn ? "" : "isLoggedIn=false (session may be expired or IP-challenged)";
      return s; // return anyway — attempt search; some sessions read fine even when isLoggedIn is flaky
    })().catch((e) => { scraperError = `init failed: ${(e?.message ?? String(e)).slice(0, 160)}`; return null; });
  }
  return scraperPromise;
}

export async function fetchTwitter(query: string, n = 15): Promise<SourceResult> {
  const src = "twitter" as const;
  const scraper = await getScraper();
  if (!scraper) return { source: src, status: "error", mentions: [], message: `twitter: ${scraperError || "unavailable"}` };
  const collect = async (): Promise<SourceResult> => {
    const mentions: Mention[] = [];
    try {
      for await (const t of scraper.searchTweets(query, n, SearchMode.Latest)) {
        const text = String((t as any).text ?? "").slice(0, 400);
        if (!text) continue;
        mentions.push({
          source: src,
          text,
          engagement: (Number((t as any).likes) || 0) + (Number((t as any).retweets) || 0) + (Number((t as any).replies) || 0),
          url: (t as any).id ? `https://x.com/i/status/${(t as any).id}` : undefined,
        });
        if (mentions.length >= n) break;
      }
    } catch (e: any) {
      if (mentions.length === 0) return { source: src, status: "error", mentions: [], message: `twitter fetch failed: ${(e?.message ?? String(e)).slice(0, 160)}` };
    }
    return { source: src, status: mentions.length ? "ok" : "empty", mentions, message: `${mentions.length} tweets` };
  };
  return withTimeout(collect(), 45_000, () => ({ source: src, status: "error", mentions: [], message: "twitter timed out" }));
}

// ---------- Reddit (public search JSON; optional cookie for higher rate limits) ----------
export async function fetchReddit(query: string, n = 12): Promise<SourceResult> {
  const src = "reddit" as const;
  const cookie = process.env.REDDIT_COOKIE;
  const url = `https://www.reddit.com/search.json?q=${encodeURIComponent(query)}&limit=${n}&sort=relevance&t=month&raw_json=1`;
  const headers: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    Accept: "application/json, text/javascript, */*; q=0.01",
  };
  if (cookie) headers["Cookie"] = cookie;
  try {
    const res = await withTimeout(fetch(url, { headers }), 20_000, () => null as any);
    if (!res) return { source: src, status: "error", mentions: [], message: "reddit timed out" };
    if (!res.ok) return { source: src, status: "error", mentions: [], message: `reddit HTTP ${res.status}` };
    const j: any = await res.json();
    const children: any[] = j?.data?.children ?? [];
    const mentions: Mention[] = children.map((c) => c.data ?? c).map((d: any) => ({
      source: src,
      text: `${d.title ?? ""} ${String(d.selftext ?? "").slice(0, 300)}`.trim().slice(0, 400),
      engagement: (Number(d.score) || 0) + (Number(d.num_comments) || 0),
      url: d.permalink ? `https://reddit.com${d.permalink}` : undefined,
    })).filter((m) => m.text);
    return { source: src, status: mentions.length ? "ok" : "empty", mentions, message: `${mentions.length} reddit posts` };
  } catch (e: any) {
    return { source: src, status: "error", mentions: [], message: `reddit fetch failed: ${(e?.message ?? String(e)).slice(0, 160)}` };
  }
}

// ---------- YouTube (yt-dlp if available; best-effort) ----------
function runCli(command: string, timeoutMs: number): Promise<{ ok: boolean; stdout: string; error?: string }> {
  return new Promise((resolve) => {
    exec(command, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      if (err) resolve({ ok: false, stdout: stdout ?? "", error: (stderr || err.message || "").slice(0, 200) });
      else resolve({ ok: true, stdout: stdout ?? "" });
    });
  });
}

export async function fetchYouTube(query: string, n = 8): Promise<SourceResult> {
  const src = "youtube" as const;
  const r = await runCli(`yt-dlp --dump-json --flat-playlist "ytsearch${n}:${safeQuery(query)}"`, 60_000);
  if (!r.ok && !r.stdout) return { source: src, status: "error", mentions: [], message: `yt-dlp unavailable: ${r.error ?? "unknown"}` };
  try {
    const mentions: Mention[] = r.stdout.split("\n").filter(Boolean).map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean).map((v: any) => ({
      source: src,
      text: String(v.title ?? "").slice(0, 300),
      engagement: Number(v.view_count) || 0,
      url: v.url || v.webpage_url,
    })).filter((m) => m.text);
    return { source: src, status: mentions.length ? "ok" : "empty", mentions, message: `${mentions.length} videos` };
  } catch (e: any) {
    return { source: src, status: "error", mentions: [], message: `parse failed: ${e?.message ?? e}` };
  }
}

/** Fetch the active sources in parallel, isolating failures.
 *  Twitter + Reddit are the wired, reliable sources. YouTube (fetchYouTube) is kept dormant: yt-dlp
 *  hard-blocks datacenter IPs, so including it would surface a persistent error rather than add signal.
 *  Re-add it here if a working yt-dlp/PO-token path is provisioned. */
export async function fetchAllSources(query: string): Promise<SourceResult[]> {
  return Promise.all([
    fetchTwitter(query).catch((e): SourceResult => ({ source: "twitter", status: "error", mentions: [], message: String(e) })),
    fetchReddit(query).catch((e): SourceResult => ({ source: "reddit", status: "error", mentions: [], message: String(e) })),
  ]);
}
