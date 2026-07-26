import { lookup } from "node:dns/promises";
import net from "node:net";

/**
 * SSRF egress guard — the single choke point for every outbound fetch to a caller-influenced URL.
 *
 * Without this, endpoints that fetch a user-supplied URL (evidence /prove, /docreview, ActionGuard
 * content) can be pointed at loopback, RFC-1918, link-local, or the cloud metadata endpoint
 * (169.254.169.254) to read internal services or steal instance credentials. This module:
 *   - allows only http/https and standard ports (80/443, or explicit 8080/8443),
 *   - resolves the hostname and blocks the request if ANY resolved IP is private/reserved,
 *   - follows redirects MANUALLY, re-validating every hop (a public URL can 302 to 127.0.0.1),
 *   - caps bytes read and wall-clock time.
 *
 * Residual note: DNS is resolved then fetched by hostname, so a determined rebinding attacker could
 * still race the two. The redirect + all-address checks close the common cases; pinning the resolved
 * IP via a custom dispatcher is the follow-up hardening.
 */

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

const DEFAULT_UA = "Aletheia-SafeFetch/1.0";
const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

/** True if an IP literal is loopback / private / link-local / reserved / metadata and must be blocked. */
export function isPrivateIp(ip: string): boolean {
  const addr = ip.trim().toLowerCase();
  if (!addr) return true;

  if (net.isIPv4(addr)) return isPrivateV4(addr);

  if (net.isIPv6(addr)) {
    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible — unwrap and check the v4 part.
    const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/) || addr.match(/^::(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped && mapped[1]) return isPrivateV4(mapped[1]);
    if (addr === "::1" || addr === "::") return true; // loopback / unspecified
    const head = addr.split(":")[0] ?? "";
    if (/^f[cd][0-9a-f]{2}$/.test(head)) return true; // fc00::/7 unique-local
    if (/^fe[89ab][0-9a-f]$/.test(head)) return true; // fe80::/10 link-local
    if (head === "ff00" || /^ff[0-9a-f]{2}$/.test(head)) return true; // multicast
    return false;
  }
  return true; // not a valid IP literal → refuse
}

function isPrivateV4(ip: string): boolean {
  const parts = ip.split(".").map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
  if (a === 192 && b === 168) return true; // 192.168/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 192 && b === 0) return true; // 192.0.0/24 (and 192.0.2/24 test-net)
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking 198.18/15
  if (a >= 224) return true; // multicast + reserved (224+/240+)
  return false;
}

/** Validate an outbound URL: scheme, port, and that every resolved IP is public. Throws SsrfError. */
export async function assertUrlAllowed(rawUrl: string): Promise<URL> {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new SsrfError(`invalid URL: ${rawUrl}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new SsrfError(`blocked scheme: ${u.protocol}`);
  if (!ALLOWED_PORTS.has(u.port)) throw new SsrfError(`blocked port: ${u.port}`);

  const host = u.hostname.replace(/^\[|\]$/g, "");
  // If the host is already an IP literal, check it directly (also catches direct-IP access).
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new SsrfError(`blocked address: ${host}`);
    return u;
  }
  // Resolve and block if ANY answer is private (defends split-horizon / multi-record rebinding).
  let addrs: { address: string }[];
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new SsrfError(`DNS resolution failed for ${host}`);
  }
  if (addrs.length === 0) throw new SsrfError(`no addresses for ${host}`);
  for (const { address } of addrs) {
    if (isPrivateIp(address)) throw new SsrfError(`${host} resolves to a blocked address (${address})`);
  }
  return u;
}

export type SafeResponse = { ok: boolean; status: number; contentType: string | null; text: string; url: string; bytes: number };

/** Fetch a caller-influenced URL safely: SSRF-checked, manual redirect re-validation, size/time caps. */
export async function safeFetch(
  rawUrl: string,
  opts: { maxBytes?: number; timeoutMs?: number; maxRedirects?: number; headers?: Record<string, string>; accept?: string } = {},
): Promise<SafeResponse> {
  const maxBytes = opts.maxBytes ?? 2_000_000;
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const maxRedirects = opts.maxRedirects ?? 3;
  let current = rawUrl;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertUrlAllowed(current); // re-validate EVERY hop, including redirect targets
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(current, {
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": DEFAULT_UA, Accept: opts.accept ?? "text/html,application/json,text/plain,*/*", ...(opts.headers ?? {}) },
      });
    } finally {
      clearTimeout(timer);
    }

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get("location");
      if (!loc) throw new SsrfError("redirect without Location");
      current = new URL(loc, current).toString();
      continue;
    }

    const contentType = res.headers.get("content-type");
    const declared = Number(res.headers.get("content-length") || "0");
    if (declared && declared > maxBytes) throw new SsrfError(`response too large (${declared} bytes)`);

    const reader = res.body?.getReader();
    if (!reader) return { ok: res.ok, status: res.status, contentType, text: "", url: current, bytes: 0 };
    const chunks: Uint8Array[] = [];
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        received += value.length;
        if (received > maxBytes) {
          await reader.cancel().catch(() => {});
          break;
        }
        chunks.push(value);
      }
    }
    const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    return { ok: res.ok, status: res.status, contentType, text: buf.subarray(0, maxBytes).toString("utf8"), url: current, bytes: received };
  }
  throw new SsrfError("too many redirects");
}
