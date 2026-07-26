/**
 * Tiny in-memory sliding-window rate limiter for free / unauthenticated demo endpoints (e.g. the
 * Creative-Genius courtroom demo, which runs an expensive deep verdict + jury). It keeps a free
 * showcase from becoming a cost / DoS vector. `now` is injectable so the window logic is unit-testable
 * without real time.
 */
const buckets = new Map<string, number[]>();

export function rateLimited(key: string, limit: number, windowMs: number, now: number = Date.now()): boolean {
  const recent = (buckets.get(key) || []).filter((t) => now - t < windowMs);
  if (recent.length >= limit) {
    buckets.set(key, recent);
    return true;
  }
  recent.push(now);
  buckets.set(key, recent);
  return false;
}

/** Test helper — clears all buckets. */
export function _resetRateLimit(): void {
  buckets.clear();
}
