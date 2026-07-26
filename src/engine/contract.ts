/**
 * Contract Audit — Trail-of-Bits-grade static analysis on any verified contract.
 *
 * Verified source is fetched from two backends, in order, for maximum coverage:
 *   1. Sourcify (free, no key; the open verified-source repo) — clean multi-file + metadata.
 *   2. Etherscan V2 (single multichain key; api.etherscan.io/v2) — the broadest verified-source DB.
 *      Follows proxies: a proxy contract's real logic lives at its implementation, so we audit that.
 *
 * Either backend yields the exact source tree + compiler settings; we pin the matching solc via
 * solc-select and run crytic/slither. Slither's ~90 detectors surface reentrancy, unprotected
 * selfdestruct, arbitrary external calls, dangerous delegatecall, tx.origin auth, unchecked transfers,
 * and the hidden mint/pause/blacklist/fee hooks that rug tokens — findings honeypot simulators miss.
 *
 * Findings fold into a GO / CAUTION / AVOID verdict with raw detector evidence attached, so it is
 * explainable and auditable. Needs the Docker image built with python3 + slither + solc-select (see
 * Dockerfile). If slither/solc are absent the call degrades to a clear, honest "engine unavailable".
 */
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import type { ChainKey } from "../config.js";

const SOURCIFY = "https://sourcify.dev/server";
const ETHERSCAN_V2 = "https://api.etherscan.io/v2/api";
const OKLINK = "https://www.oklink.com/api/v5/explorer/contract/verify-contract-info";
// chains served by OKLink (X Layer is OKLink-only; not on Etherscan V2). chainShortName per OKLink.
const OKLINK_SHORT: Record<string, string> = { xlayer: "XLAYER" };
// chainids shared by Sourcify and Etherscan V2. X Layer (196) is OKLink-only (not on Etherscan V2).
const CHAIN_ID: Record<string, number> = {
  ethereum: 1, bsc: 56, polygon: 137, arbitrum: 42161, base: 8453, xlayer: 196, optimism: 10, avalanche: 43114,
};
// which chainids Etherscan V2 actually serves (used to skip the call for X Layer etc.)
const ETHERSCAN_CHAINS = new Set([1, 56, 137, 42161, 8453, 10, 43114]);

type SlitherDetector = { check: string; impact: string; confidence: string; description: string };
export type VerifiedSource = {
  provider: "sourcify" | "etherscan" | "oklink";
  compilerVersion: string;
  name: string;
  target: string; // best-guess entry file; "" → analyze the whole tree
  remappings: string[];
  sources: Record<string, { content: string }>;
  proxyOf?: string; // the proxy address, when this source is the implementation behind it
  implAddress?: string; // the implementation address that was actually fetched/audited
};
export type ContractAudit = {
  ok: boolean;
  observed_at: string;
  chain: string;
  address: string;
  verified: boolean;
  source?: "sourcify" | "etherscan" | "oklink";
  proxy_implementation?: string;
  verdict: "GO" | "CAUTION" | "AVOID" | "UNKNOWN";
  score: number; // 0..100, higher = safer
  contract_name?: string;
  compiler?: string;
  detectors_run?: number;
  findings: { severity: "high" | "medium" | "low" | "info"; check: string; confidence: string; detail: string }[];
  summary: string;
  engine: "slither" | "unavailable";
  trace_id?: string;
  error?: string;
};

const IMPACT_RANK: Record<string, "high" | "medium" | "low" | "info"> = {
  High: "high", Medium: "medium", Low: "low", Informational: "info", Optimization: "info",
};

/** Normalize any Etherscan `SourceCode` field (flattened, sources-map, or double-wrapped standard-JSON)
 *  into a uniform {sources, remappings}. Pure + exported so it is unit-testable without a network call. */
export function parseEtherscanSource(raw: string, contractName: string): { sources: Record<string, { content: string }>; remappings: string[] } {
  const name = /\.sol$/i.test(contractName) ? contractName : `${contractName || "Contract"}.sol`;
  const flat = (): { sources: Record<string, { content: string }>; remappings: string[] } => ({ sources: { [name]: { content: raw } }, remappings: [] });
  const s = (raw || "").trim();
  if (!s) return { sources: {}, remappings: [] };
  if (!s.startsWith("{")) return flat();
  // double-wrapped standard-JSON: Etherscan wraps the compiler input in an extra pair of braces
  const body = s.startsWith("{{") && s.endsWith("}}") ? s.slice(1, -1) : s;
  let obj: any;
  try { obj = JSON.parse(body); } catch { return flat(); }
  const norm = (src: Record<string, any>): Record<string, { content: string }> => {
    const out: Record<string, { content: string }> = {};
    for (const [path, v] of Object.entries(src)) out[path] = { content: typeof v === "string" ? v : String(v?.content ?? "") };
    return out;
  };
  // standard-JSON input: { language, sources: {path:{content}}, settings:{remappings} }
  if (obj && typeof obj === "object" && obj.sources && typeof obj.sources === "object") {
    return { sources: norm(obj.sources), remappings: Array.isArray(obj.settings?.remappings) ? obj.settings.remappings.map(String) : [] };
  }
  // bare sources-map: { "path.sol": {content} } — heuristic: values look like {content} or code strings
  if (obj && typeof obj === "object") {
    const vals = Object.values(obj);
    const looksLikeSources = vals.length > 0 && vals.every((v) => typeof v === "string" || (v && typeof v === "object" && "content" in (v as object)));
    if (looksLikeSources) return { sources: norm(obj as Record<string, any>), remappings: [] };
  }
  return flat();
}

/** Pick the source file that defines `contractName` (else first .sol) as slither's entry target. */
function pickTarget(sources: Record<string, unknown>, contractName: string): string {
  const paths = Object.keys(sources);
  const want = `${contractName}.sol`.toLowerCase();
  const exact = paths.find((p) => p.toLowerCase().endsWith("/" + want) || p.toLowerCase() === want);
  return exact || paths.find((p) => /\.sol$/i.test(p)) || paths[0] || "";
}

/** Sourcify v2 (null if not verified / chain unsupported). */
async function fetchFromSourcify(chainId: number, address: string): Promise<VerifiedSource | null> {
  const url = `${SOURCIFY}/v2/contract/${chainId}/${address}?fields=compilation,sources`;
  const r = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15_000) }).catch(() => null);
  if (!r || !r.ok) return null;
  const j: any = await r.json().catch(() => null);
  if (!j?.compilation || !j?.sources) return null;
  const comp = j.compilation;
  const name = String(comp.name || String(comp.fullyQualifiedName || "").split(":").pop() || "Contract");
  return {
    provider: "sourcify",
    compilerVersion: String(comp.compilerVersion || "").replace(/^v/, ""),
    name,
    target: String(comp.fullyQualifiedName || "").split(":")[0] || pickTarget(j.sources, name),
    remappings: Array.isArray(comp.compilerSettings?.remappings) ? comp.compilerSettings.remappings.map(String) : [],
    sources: j.sources,
  };
}

type EtherscanResult = { SourceCode: string; ContractName: string; CompilerVersion: string; Proxy?: string; Implementation?: string };

async function etherscanGetSource(chainId: number, address: string, apiKey: string): Promise<EtherscanResult | null> {
  const url = `${ETHERSCAN_V2}?chainid=${chainId}&module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
  const r = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15_000) }).catch(() => null);
  if (!r || !r.ok) return null;
  const j: any = await r.json().catch(() => null);
  const res = Array.isArray(j?.result) ? j.result[0] : null;
  if (!res || !res.SourceCode || res.ABI === "Contract source code not verified") return null;
  return res as EtherscanResult;
}

/** Etherscan V2 source fetch for one address (needs ETHERSCAN_API_KEY). No proxy logic here —
 *  proxy resolution happens up-front in resolveProxyTarget so it applies to the Sourcify path too. */
async function fetchFromEtherscan(chainId: number, address: string, apiKey: string): Promise<VerifiedSource | null> {
  if (!ETHERSCAN_CHAINS.has(chainId)) return null;
  const res = await etherscanGetSource(chainId, address, apiKey);
  if (!res) return null;
  const { sources, remappings } = parseEtherscanSource(res.SourceCode, res.ContractName);
  if (Object.keys(sources).length === 0) return null;
  return {
    provider: "etherscan",
    compilerVersion: String(res.CompilerVersion || "").replace(/^v/, ""),
    name: String(res.ContractName || "Contract"),
    target: pickTarget(sources, String(res.ContractName || "")),
    remappings,
    sources,
  };
}

type OklinkResult = { sourceCode: string; contractName: string; compilerVersion: string; proxy?: string; implementation?: string };

/** OKLink verified-source lookup (X Layer). No auth required. Null if unverified / not found. */
async function oklinkGetSource(shortName: string, address: string): Promise<OklinkResult | null> {
  const url = `${OKLINK}?chainShortName=${shortName}&contractAddress=${address}`;
  const r = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15_000) }).catch(() => null);
  if (!r || !r.ok) return null;
  const j: any = await r.json().catch(() => null);
  const res = j?.code === "0" && Array.isArray(j?.data) ? j.data[0] : null;
  if (!res || !res.sourceCode) return null;
  return res as OklinkResult;
}

/** Build a VerifiedSource from OKLink, following a proxy to its implementation (X Layer coverage). */
async function fetchFromOklink(shortName: string, address: string): Promise<VerifiedSource | null> {
  let res = await oklinkGetSource(shortName, address);
  if (!res) return null;
  let proxyOf: string | undefined, implAddress: string | undefined;
  const impl = String(res.implementation || "").trim();
  if (res.proxy === "1" && /^0x[a-fA-F0-9]{40}$/.test(impl) && impl.toLowerCase() !== address.toLowerCase() && !/^0x0+$/.test(impl)) {
    const behind = await oklinkGetSource(shortName, impl);
    if (behind) { res = behind; proxyOf = address; implAddress = impl; }
  }
  const { sources, remappings } = parseEtherscanSource(res.sourceCode, res.contractName);
  if (Object.keys(sources).length === 0) return null;
  return {
    provider: "oklink",
    compilerVersion: String(res.compilerVersion || "").replace(/^v/, ""),
    name: String(res.contractName || "Contract"),
    target: pickTarget(sources, String(res.contractName || "")),
    remappings, sources, proxyOf, implAddress,
  };
}

function runCmd(cmd: string, args: string[], opts: { cwd?: string; timeoutMs: number }): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { cwd: opts.cwd, env: process.env });
    let stdout = "", stderr = "";
    const t = setTimeout(() => { try { p.kill("SIGKILL"); } catch {} }, opts.timeoutMs);
    p.stdout.on("data", (d) => (stdout += d.toString()));
    p.stderr.on("data", (d) => (stderr += d.toString()));
    p.on("error", (e) => { clearTimeout(t); resolve({ code: -1, stdout, stderr: stderr + String(e) }); });
    p.on("close", (code) => { clearTimeout(t); resolve({ code: code ?? -1, stdout, stderr }); });
  });
}

// Whole-audit wall-clock budget, kept safely under the x402 maxTimeoutSeconds (300s) the endpoint
// advertises. Normal contracts finish in well under a minute; only pathologically large ones approach
// this. Without it, a primary + fallback slither stack could run 500s+ and blow the payment window —
// with it, an oversized contract returns an honest "couldn't fully audit" instead. Env-tunable.
const AUDIT_BUDGET_MS = Number(process.env.VERITY_AUDIT_BUDGET_MS ?? 240_000);
const remainingMs = (deadline: number): number => Math.max(0, deadline - Date.now());

function rank(s: string): number { return s === "high" ? 3 : s === "medium" ? 2 : s === "low" ? 1 : 0; }
/** Strip build-scratch and machine paths from Slither descriptions so evidence reads cleanly. */
function cleanPaths(s: string): string {
  return s
    // crytic names fetched files crytic-export/etherscan-contracts/0x<addr><chain>-<Name>.sol
    .replace(/(?:\.\.\/)*crytic-export\/etherscan-contracts\/0x[0-9a-fA-F]{40}[a-z]*-/g, "")
    .replace(/[\w@.\-/]*\/([\w.\-]+\.sol)/g, "$1"); // collapse any remaining path to its filename
}
function shortSolc(v: string): string { return ((v || "").replace(/^v/, "").match(/^\d+\.\d+\.\d+/) || ["0.8.20"])[0]; }

// crytic-compile Etherscan V2 network prefixes (from its SUPPORTED_NETWORK_V2). X Layer is not on
// Etherscan V2 → stays Sourcify-only.
const NETWORK_PREFIX: Record<string, string> = {
  ethereum: "mainnet", bsc: "bsc", polygon: "poly", arbitrum: "arbi", base: "base", optimism: "optim", avalanche: "avax",
};

/** Parse a `slither --json -` stdout into its detector array; null if slither didn't produce results. */
function parseDetectors(stdout: string): SlitherDetector[] | null {
  const i = stdout.indexOf("{");
  if (i < 0 || !stdout.includes('"results"')) return null;
  try { return (JSON.parse(stdout.slice(i))?.results?.detectors ?? []) as SlitherDetector[]; } catch { return null; }
}

type VerdictCtx = { chain: string; address: string; observed_at: string; source: "sourcify" | "etherscan" | "oklink"; name: string; compiler: string; proxyOf?: string; implAddress?: string };

/** Fold Slither's detectors into a GO/CAUTION/AVOID verdict + evidence (shared by both runners). */
function shapeVerdict(dets: SlitherDetector[], ctx: VerdictCtx): ContractAudit {
  const findings = dets.map((d) => ({
    severity: IMPACT_RANK[d.impact] ?? "info",
    check: d.check,
    confidence: d.confidence,
    detail: cleanPaths(d.description || "").replace(/\n+/g, " ").trim().slice(0, 400),
  })).sort((a, b) => rank(b.severity) - rank(a.severity));
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;
  // Slither's detectors degrade badly on pre-0.6 Solidity (old AST/IR) — many silently don't fire,
  // so an absence of findings is NOT a clean bill of health. Never hand out a confident GO we can't
  // stand behind (a false "clean" on a vulnerable old contract is worse than an honest "can't tell").
  const mv = (ctx.compiler || "").match(/(\d+)\.(\d+)/);
  const oldSolc = mv ? (Number(mv[1]) === 0 && Number(mv[2]) < 5) : false;
  const limited = oldSolc && high === 0 && med === 0;
  let verdict: ContractAudit["verdict"] = high > 0 ? "AVOID" : med > 0 ? "CAUTION" : "GO";
  let score = Math.max(0, 100 - high * 35 - med * 12 - low * 3);
  if (high > 0) score = Math.min(score, 20); // an AVOID must not read as a mid score (consistent w/ other modules)
  if (limited) { verdict = "CAUTION"; score = Math.min(score, 55); }
  const trace_id = createHash("sha256").update(`${ctx.chain}:${ctx.address}:${JSON.stringify(dets)}`).digest("hex");
  const proxyNote = ctx.proxyOf ? ` (proxy - audited implementation ${ctx.name} at ${ctx.implAddress})` : "";
  return {
    ok: true, observed_at: ctx.observed_at, chain: ctx.chain, address: ctx.address, verified: true, source: ctx.source,
    proxy_implementation: ctx.implAddress, verdict, score, contract_name: ctx.name, compiler: ctx.compiler, detectors_run: dets.length,
    findings: findings.slice(0, 40),
    summary: high > 0
      ? `AVOID - ${high} high-severity issue(s) (${findings.filter((f) => f.severity === "high").map((f) => f.check).slice(0, 3).join(", ")})${proxyNote}. Do not interact without a manual review.`
      : med > 0
      ? `CAUTION - no critical bugs, but ${med} medium-severity finding(s)${proxyNote} worth understanding before you trust it.`
      : limited
      ? `LIMITED ANALYSIS - this contract compiles with an outdated Solidity (${ctx.compiler}) that modern static analysis covers poorly. Slither surfaced no high/medium issues, but on legacy compilers that is NOT a clean bill of health${proxyNote}. Treat as unverified and review manually before trusting it.`
      : `GO - Slither found no high or medium-severity issues across ${dets.length} detector families${proxyNote}.`,
    engine: "slither", trace_id,
  };
}

/** PRIMARY engine: let crytic-compile fetch + compile from Etherscan V2 itself (handles the messy
 *  path/import/compiler normalization that hand-reconstruction cannot). Returns detectors or null. */
async function runNativeEtherscan(prefix: string, target: string, apiKey: string, compiler: string, deadline: number): Promise<SlitherDetector[] | null> {
  const dir = await mkdtemp(join(tmpdir(), "audit-es-")); // isolates crytic-export cache; removed after
  try {
    if (compiler) await runCmd("solc-select", ["install", compiler], { timeoutMs: Math.min(120_000, remainingMs(deadline)) });
    const slitherBudget = remainingMs(deadline);
    if (slitherBudget < 5_000) return null; // out of time budget → let the caller return a graceful result
    const res = await runCmd("slither", [`${prefix}:${target}`, "--etherscan-apikey", apiKey, "--json", "-"], { cwd: dir, timeoutMs: Math.min(220_000, slitherBudget) });
    return parseDetectors(res.stdout);
  } catch { return null; } finally { await rm(dir, { recursive: true, force: true }).catch(() => {}); }
}

/** Some explorers (OKLink) store sources by basename while imports still use full paths
 *  ("proxy/utils/Initializable.sol"). When keys are flat, rewrite imports to "./<basename>" so
 *  solc can resolve them; a no-op when the tree already has real directories. */
function normalizeImports(sources: Record<string, { content: string }>): Record<string, { content: string }> {
  const keys = Object.keys(sources);
  if (keys.length === 0 || keys.some((k) => k.includes("/"))) return sources;
  const names = new Set(keys);
  const out: Record<string, { content: string }> = {};
  for (const [k, v] of Object.entries(sources)) {
    const content = String((v as any).content ?? "").replace(/(\bimport\b[^;]*?["'])([^"']+)(["'])/g, (m, pre, p, post) => {
      const base = String(p).split("/").pop() || p;
      return names.has(base) ? `${pre}./${base}${post}` : m;
    });
    out[k] = { content };
  }
  return out;
}

/** Find the source file that actually defines `name` (the contract/library/interface), so slither
 *  gets the real entry point — filenames often don't match the contract name (e.g. OKLink trees). */
function findEntryFile(sources: Record<string, { content: string }>, name: string): string {
  if (!name) return "";
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`\\b(?:abstract\\s+contract|contract|library|interface)\\s+${esc}\\b`);
  for (const [k, v] of Object.entries(sources)) if (re.test(String(v.content ?? ""))) return k;
  return "";
}

/** FALLBACK engine: reconstruct the source tree locally and run slither via the file-based solc
 *  platform on the true entry file (imports rewritten to resolve). Used for X Layer, no-key, or a
 *  native-fetch miss. crytic-compile's solc-json platform is avoided — it mis-matches source units. */
async function runLocalReconstruct(src: VerifiedSource, chain: string, address: string, observed_at: string, deadline: number): Promise<ContractAudit> {
  const base: ContractAudit = { ok: false, observed_at, chain, address, verified: true, source: src.provider, verdict: "UNKNOWN", score: 0, findings: [], summary: "", engine: "slither", contract_name: src.name, proxy_implementation: src.implAddress };
  const shortVer = shortSolc(src.compilerVersion);
  const sources = normalizeImports(src.sources);
  const dir = await mkdtemp(join(tmpdir(), "audit-"));
  try {
    for (const [path, s] of Object.entries(sources)) {
      const safe = path.replace(/^\/+/, "").replace(/\.\.(\/|\\)/g, "");
      const abs = join(dir, safe);
      await mkdir(dirname(abs), { recursive: true });
      await writeFile(abs, (s as any).content ?? "", "utf8");
    }
    await runCmd("solc-select", ["install", shortVer], { timeoutMs: Math.min(120_000, remainingMs(deadline)) });
    await runCmd("solc-select", ["use", shortVer], { timeoutMs: Math.min(20_000, remainingMs(deadline)) });

    // entry = the file that declares the main contract (content match), else the named-file guess
    const entry = (findEntryFile(sources, src.name) || (src.target && /\.sol$/i.test(src.target) ? src.target : "")).replace(/^\/+/, "");
    const remaps = src.remappings.length ? ["--solc-remaps", src.remappings.join(" ")] : [];
    // Stay inside the overall audit budget: cap each slither pass to the time left, and if the budget is
    // already spent, return an honest "couldn't fully audit" instead of running past the payment window.
    const budget1 = remainingMs(deadline);
    if (budget1 < 5_000) return { ...base, compiler: shortVer, engine: "unavailable", summary: "Static analysis exceeded its time budget for this contract (verified source exists but is too large to fully audit within the payment window). Treat as unaudited and review manually before trusting it.", error: "time_budget_exceeded" };
    let res = entry ? await runCmd("slither", [entry, "--json", "-", ...remaps], { cwd: dir, timeoutMs: Math.min(180_000, budget1) }) : { code: -1, stdout: "", stderr: "" };
    let dets = parseDetectors(res.stdout);
    if (!dets) {
      const budget2 = remainingMs(deadline);
      if (budget2 >= 5_000) { res = await runCmd("slither", [".", "--json", "-", ...remaps], { cwd: dir, timeoutMs: Math.min(180_000, budget2) }); dets = parseDetectors(res.stdout); }
    }
    if (!dets) return { ...base, compiler: shortVer, engine: "unavailable", summary: "Static analyzer could not compile this source (compiler/import edge case). Verified source exists but was not machine-auditable this run.", error: (res.stderr || "no analyzer output").slice(0, 300) };
    return shapeVerdict(dets, { chain, address, observed_at, source: src.provider, name: src.name, compiler: shortVer, proxyOf: src.proxyOf, implAddress: src.implAddress });
  } catch (e: any) {
    return { ...base, compiler: shortVer, engine: "unavailable", summary: "Audit engine error.", error: (e?.message ?? String(e)).slice(0, 300) };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** Audit a deployed, verified contract with Slither. Native crytic-compile Etherscan fetch is the
 *  primary engine (robust); Sourcify local reconstruction is the fallback (X Layer / no key). */
export async function auditContract(chain: ChainKey, address: string): Promise<ContractAudit> {
  const observed_at = new Date().toISOString();
  const deadline = Date.now() + AUDIT_BUDGET_MS; // whole-audit wall-clock cap, safely under maxTimeoutSeconds (300s)
  const base: ContractAudit = { ok: false, observed_at, chain, address, verified: false, verdict: "UNKNOWN", score: 0, findings: [], summary: "", engine: "slither" };
  const chainId = CHAIN_ID[chain];
  if (!chainId) return { ...base, error: `Contract Audit not wired for chain ${chain}` };
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return { ...base, error: "invalid EVM address" };

  const apiKey = process.env.ETHERSCAN_API_KEY || "";
  const prefix = NETWORK_PREFIX[chain];
  const okShort = OKLINK_SHORT[chain];

  // === OKLink-only chains (X Layer): OKLink verified source (proxy-aware) → local reconstruction.
  //     Sourcify is a secondary source for the rare X Layer contract verified there instead. ===
  if (okShort && !prefix) {
    let src = await fetchFromOklink(okShort, address);
    if (!src) src = await fetchFromSourcify(chainId, address);
    if (!src) return { ...base, verdict: "UNKNOWN", summary: "No verified source published for this contract on OKLink or Sourcify - cannot statically audit. Treat unverified code as unaudited.", engine: "unavailable", error: "source_not_verified" };
    return runLocalReconstruct(src, chain, address, observed_at, deadline);
  }

  // resolve proxies + fetch target metadata (name, compiler) from Etherscan when available
  let target = address, proxyOf: string | undefined, implAddress: string | undefined, name = "Contract", compiler = "";
  if (apiKey && ETHERSCAN_CHAINS.has(chainId)) {
    const res0 = await etherscanGetSource(chainId, address, apiKey).catch(() => null);
    const impl = String(res0?.Implementation || "").trim();
    if (res0?.Proxy === "1" && /^0x[a-fA-F0-9]{40}$/.test(impl) && impl.toLowerCase() !== address.toLowerCase() && !/^0x0+$/.test(impl)) {
      target = impl; proxyOf = address; implAddress = impl;
      const resI = await etherscanGetSource(chainId, impl, apiKey).catch(() => null);
      name = String(resI?.ContractName || res0.ContractName || "Contract"); compiler = shortSolc(resI?.CompilerVersion || "");
    } else if (res0) {
      name = String(res0.ContractName || "Contract"); compiler = shortSolc(res0.CompilerVersion || "");
    }
  }

  // PRIMARY: native crytic-compile Etherscan fetch (proven robust on multi-file + proxies)
  if (apiKey && prefix) {
    const dets = await runNativeEtherscan(prefix, target, apiKey, compiler, deadline);
    if (dets) return shapeVerdict(dets, { chain, address, observed_at, source: "etherscan", name, compiler, proxyOf, implAddress });
    // else fall through to the reconstruction engine
  }

  // FALLBACK: Sourcify (clean multi-file) → Etherscan reconstruction; used for X Layer / no key / native miss
  let src = await fetchFromSourcify(chainId, target);
  if (!src && apiKey) src = await fetchFromEtherscan(chainId, target, apiKey);
  if (!src) {
    const reason = apiKey
      ? "No verified source published for this contract on Sourcify or Etherscan - cannot statically audit. Treat unverified code as unaudited."
      : "No verified source on Sourcify, and Etherscan lookup is not configured (set ETHERSCAN_API_KEY for full coverage). Treat unverified code as unaudited.";
    return { ...base, verdict: "UNKNOWN", summary: reason, engine: "unavailable", error: "source_not_verified" };
  }
  if (proxyOf) { src.proxyOf = proxyOf; src.implAddress = implAddress; }
  return runLocalReconstruct(src, chain, address, observed_at, deadline);
}
