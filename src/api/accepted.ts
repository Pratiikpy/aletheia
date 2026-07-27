/**
 * What each paid route actually reads, and the notice for anything else.
 *
 * A field whose name is not recognised is dropped and the route's default used instead, silently.
 * Measured on sibling ASPs: a misspelled key turned a request for two venues into five computed from
 * defaults, and a 120-character cap into 8,079 characters. Nothing in either response said the field
 * had been discarded, so the caller was answered a different question from the one they paid for.
 *
 * The accepted set is the union of two sources on purpose: every `body.x` a handler touches, and
 * every field the published `Input:` contract promises. Built from only the first it would flag
 * documented fields a handler forwards to a helper — `/actionguard` reads `type` directly and passes
 * the rest on — and a checker that fires on correct calls trains the caller to ignore it, which is
 * worse than not having one. Generous by construction: a missed field costs a warning nobody needed,
 * a wrongly included one costs nothing at all.
 *
 * Kept in its own module so it can be tested without booting the HTTP server.
 */

export const ACCEPTED_FIELDS: Record<string, string[]> = {
  "/verdict": ["address", "chain", "tier"],
  "/check": ["address", "chain", "content", "subject", "tx", "url"],
  "/settle": ["dispute", "question", "sideA", "sideB", "side_a", "side_b", "subject"],
  "/kol": ["handle", "subject", "username"],
  "/report": ["address", "chain"],
  "/watch/check": ["address", "chain", "previous_snapshot"],
  "/attest": ["address", "chain"],
  // The contract documents "type, plus the matching fields (to/data/value, content/url, or
  // chain/address)" — prose the handler resolves downstream, so all of them are accepted here.
  "/actionguard": ["type", "to", "data", "value", "content", "url", "chain", "address"],
  "/impersonation": ["brand", "official_domain"],
  "/verify": ["answer", "question"],
  "/docreview": ["text", "url"],
  "/pretx": ["chain", "data", "to", "value"],
  "/firewall/content": ["content"],
  "/firewall": ["chain", "data", "from", "to", "value"],
  "/repo": ["repo", "repository", "url"],
  "/prove": ["query", "url"],
  "/audit": ["apiKey", "api_key", "baseUrl", "endpoint", "headers", "model", "system",
             "pricing_input_per_m", "pricing_output_per_m"],
  "/ask": ["chain", "q", "query", "question", "subject"],
  "/research": ["address", "chain", "claim", "query", "question", "subject", "topic", "url"],
  "/dyor": ["address", "chain"],
  "/wallet-report": ["address", "chain"],
  "/tx-report": ["chain", "data", "from", "to", "value"],
  "/wallet-health": ["address", "chain"],
  "/contract-audit": ["address", "chain"],
};

/** Damerau-Levenshtein distance: insertions, deletions, substitutions **and adjacent swaps**.
 *
 *  The swap is the whole reason this is not plain Levenshtein. `teir` for `tier` is one transposition
 *  and the commonest typo there is, but plain Levenshtein scores it 2 — two substitutions — which put
 *  it outside any threshold tight enough to be useful on four-letter field names. Counting a swap as
 *  one keeps the threshold strict and still catches the case that actually happens.
 *
 *  Strings here are field names, so the full matrix costs nothing worth optimising.
 */
function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 },
                                   () => new Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) d[i]![0] = i;
  for (let j = 0; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let best = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, d[i - 2]![j - 2]! + 1);          // adjacent transposition
      }
      d[i]![j] = best;
    }
  }
  return d[a.length]![b.length]!;
}

/** The closest accepted field to a misspelling, or null when nothing is close enough.
 *
 *  Edit distance rather than a shared prefix. A prefix rule looked adequate and silently failed on
 *  the single commonest typo there is: `teir` and `tier` agree on one character before diverging, so
 *  a transposition scored no better than an unrelated word and produced no suggestion at all. Caught
 *  by the test for exactly that case.
 *
 *  The threshold scales with length so short fields are not matched to everything, and a wrong guess
 *  costs only a hint the caller can ignore. */
function nearest(key: string, accepted: string[]): string | null {
  const limit = key.length <= 4 ? 1 : key.length <= 8 ? 2 : 3;
  let best: string | null = null;
  let bestDistance = Infinity;
  for (const candidate of accepted) {
    const d = editDistance(key.toLowerCase(), candidate.toLowerCase());
    if (d <= limit && d < bestDistance) {
      bestDistance = d;
      best = candidate;
    }
  }
  return best;
}

/** Name any field this route does not read, suggesting the closest one it does. */
export function ignoredInputNote(path: string, body: unknown): string | null {
  const accepted = ACCEPTED_FIELDS[path];
  if (!accepted || !body || typeof body !== "object" || Array.isArray(body)) return null;
  const unknown = Object.keys(body as Record<string, unknown>)
    .filter((k) => !accepted.includes(k))
    .sort();
  if (!unknown.length) return null;

  const hints = unknown.map((k) => {
    const n = nearest(k, accepted);
    return n ? `'${k}' (did you mean '${n}'?)` : `'${k}'`;
  });
  return `Ignored, because this endpoint does not read ${unknown.length > 1 ? "them" : "it"}: `
    + `${hints.join(", ")}. The default was used instead, so this answer may not be the one you `
    + `intended. Accepted fields: ${[...accepted].sort().join(", ")}.`;
}
