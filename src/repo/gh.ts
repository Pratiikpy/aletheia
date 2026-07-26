/** GitHub REST API data layer for RepoRadar. Uses plain fetch — works keyless for public repos
 *  (60 req/hr per IP; ~12 scans/hr), and honors GH_TOKEN for 5000 req/hr when one is set. No `gh`
 *  CLI dependency, so it runs anywhere (incl. the Docker container). */
export async function ghJson(apiPath: string, opts: { timeoutMs?: number; paginate?: boolean } = {}): Promise<any | null> {
  const first = apiPath.startsWith("http") ? apiPath : `https://api.github.com/${apiPath.replace(/^\/+/, "")}`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "AletheiaRepoRadar/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GH_TOKEN) headers.Authorization = `Bearer ${process.env.GH_TOKEN}`;
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), opts.timeoutMs ?? 20_000);
  try {
    let out: any = null;
    let next: string | null = first;
    const maxPages = opts.paginate ? 3 : 1; // bound cost; 3×per_page is ample signal
    for (let page = 0; next && page < maxPages; page++) {
      const res: Response = await fetch(next, { headers, signal: controller.signal });
      if (!res.ok) return page > 0 ? out : null; // 404/403/rate-limit on the first page → null
      const j = await res.json().catch(() => null);
      if (j == null) break;
      if (Array.isArray(j)) { out = Array.isArray(out) ? out.concat(j) : j; }
      else { return j; } // repo object / readme / tree → single response
      const link = res.headers.get("link") || "";
      const m = link.match(/<([^>]+)>;\s*rel="next"/);
      next = m?.[1] ?? null;
    }
    return out;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** Parse an owner/repo from a URL or shorthand. */
export function parseRepo(input: string): string | null {
  const s = input.trim().replace(/\.git$/, "");
  const m = s.match(/github\.com[/:]([^/]+)\/([^/#?]+)/i) || s.match(/^([\w.-]+)\/([\w.-]+)$/);
  return m ? `${m[1]}/${m[2]}` : null;
}
