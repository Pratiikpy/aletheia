/**
 * TTL cache with in-flight de-duplication for expensive verdict computations (fork sim + jury).
 *
 * Two wins for agent callers (who time out ~10s and call in bursts):
 *  1. TTL reuse — an identical (chain, address, tier) call within `ttlMs` returns the cached envelope
 *     instantly instead of re-running the simulation.
 *  2. In-flight dedup — concurrent identical calls share ONE computation (no thundering herd spawning
 *     N Anvil forks for the same token at once).
 *
 * TTL is deliberately short (default 60s) so a pre-trade safety verdict is never meaningfully stale;
 * every envelope also carries `generated_at` so the caller sees freshness. `now` is injectable for tests.
 */
type Entry<T> = { at: number; value: T };

const store = new Map<string, Entry<unknown>>();
const inflight = new Map<string, Promise<unknown>>();

export async function cached<T>(
  key: string,
  ttlMs: number,
  produce: () => Promise<T>,
  now: () => number = Date.now,
): Promise<T> {
  const hit = store.get(key) as Entry<T> | undefined;
  if (hit && now() - hit.at < ttlMs) return hit.value;

  const pending = inflight.get(key) as Promise<T> | undefined;
  if (pending) return pending;

  const p = (async () => {
    try {
      const value = await produce();
      store.set(key, { at: now(), value });
      return value;
    } finally {
      inflight.delete(key);
    }
  })();
  inflight.set(key, p);
  return p;
}

/** Test helper — clears cache + in-flight state. */
export function _resetCache(): void {
  store.clear();
  inflight.clear();
}
