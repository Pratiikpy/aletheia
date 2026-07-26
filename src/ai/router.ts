import { config } from "../config.js";

/**
 * 0G Compute model router — OpenAI-compatible, decentralized inference.
 * Task-tiered: cheap model for extraction/flag, strong for fusion/reports, jury for bull-vs-bear.
 */

export type ModelTier = "cheap" | "strong" | "alt" | "reasoning";

/** Strip inline <think> reasoning some models emit. Handles complete blocks and truncated/dangling forms. */
function stripThink(s: string): string {
  let out = s.replace(/<think>[\s\S]*?<\/think>/gi, "");
  if (!out.includes("<think>") && out.includes("</think>")) out = out.slice(out.lastIndexOf("</think>") + 8); // dangling close
  if (out.includes("<think>") && !out.includes("</think>")) out = out.slice(0, out.indexOf("<think>")); // dangling open (truncated)
  return out.trim();
}

type ChatMsg = { role: "system" | "user" | "assistant"; content: string };

function modelFor(tier: ModelTier): string {
  return config.zg.models[tier];
}

/**
 * Ordered fallback models, tried when the CHOSEN model itself cannot serve.
 *
 * Why: the router answers `403 BALANCE_INSUFFICIENT` per-model, not per-account. Reach's paid
 * /research returned a 500 to a user who had already been charged, purely because its single
 * configured model was balance-gated while other models on the same key served normally. Every paid
 * endpoint here funnels through this function, so one gated model would take the whole ASP down the
 * same way. Each name below was verified to answer a real tool-using call on this account.
 */
const FALLBACK_MODELS: string[] = (process.env.ZG_FALLBACK_MODELS ??
  "glm-5.2,deepseek-v4-pro,qwen3.7-max,minimax-m3,hy3,deepseek-v4-flash")
  .split(",").map((s) => s.trim()).filter(Boolean);

/** Does this error mean "this MODEL cannot serve", as opposed to "this REQUEST was bad"? */
function isModelUnavailable(status: number | null, err: any): boolean {
  const blob = String(err?.message ?? err ?? "").toLowerCase();
  if (status === 403 || status === 404 || status === 402) return true;
  // A dialect mismatch arrives as a 400, not a 403: the router answers
  // "model 'claude-fable-5' is not available on the openai API format (supported: [anthropic])".
  // That is still the MODEL being unusable here, so it must fall through to the next candidate
  // instead of failing a paid call.
  return /balance_insufficient|insufficient|model_not_found|no provider|unsupported model|quota|not available on the|api format/
    .test(blob);
}

// ---- Load hardening for the shared 0G router (the one choke point every endpoint funnels through) ----
// 1) Concurrency cap: too many simultaneous inference calls make the router queue and time out (the
//    burst-load failure). We admit at most N at once; the rest wait for a slot, so bursts degrade to
//    "a bit slower" instead of "empty response". 2) Retry with backoff on TRANSIENT errors only
//    (429/5xx/timeout/network) — permanent 4xx (bad request/auth) fail fast. 3) Per-call timeout kept.
const MAX_CONCURRENT = Math.max(1, Number(process.env.ZG_MAX_CONCURRENT ?? 8));
let active = 0;
const waiters: (() => void)[] = [];
async function acquire(): Promise<void> {
  if (active < MAX_CONCURRENT) { active++; return; }
  await new Promise<void>((resolve) => waiters.push(resolve)); // slot handed over on release; count unchanged
}
function release(): void {
  const next = waiters.shift();
  if (next) next(); // hand the slot straight to the next waiter (active stays ≤ MAX_CONCURRENT)
  else active--;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function isTransient(status: number | null, err: any): boolean {
  if (status != null) return [408, 425, 429, 500, 502, 503, 504].includes(status); // retry these; other 4xx are permanent
  const m = String(err?.name ?? "") + " " + String(err?.message ?? err ?? "").toLowerCase();
  return /abort|timeout|timed out|network|fetch failed|econnreset|econnrefused|socket|eai_again|und_err/.test(m);
}

export async function chat(
  messages: ChatMsg[],
  opts: { tier?: ModelTier; model?: string; temperature?: number; maxTokens?: number; json?: boolean; timeoutMs?: number; verifyTee?: boolean } = {}
): Promise<{ content: string; model: string; usage?: any; costWei?: string; teeVerified?: boolean; provider?: string }> {
  const tier = opts.tier ?? "strong";
  const preferred = opts.model ?? modelFor(tier); // explicit model wins (used by the diverse jury)
  // Try the preferred model first, then any fallback not already tried. A gated model must not take a
  // paid endpoint down (see FALLBACK_MODELS).
  const candidates = [preferred, ...FALLBACK_MODELS.filter((m) => m !== preferred)];
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const MAX_ATTEMPTS = 3;
  // NOTE: TEE attestation is NOT available on the 0G Router path we use (only via the Direct serving-broker
  // SDK). So we never claim TEE verification on router calls: `teeVerified` is always false.
  await acquire();
  try {
    let lastErr: any;
    for (const model of candidates) {
    // Per-model: how many output tokens to ask for, and whether we already raised it once because the
    // model returned nothing but reasoning.
    let tokenBudget: number | undefined = opts.maxTokens;
    let escalated = false;
    for (let attempt = 0; attempt < MAX_ATTEMPTS + 1; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const body: any = { model, messages, temperature: opts.temperature ?? 0.2 };
        if (tokenBudget) body.max_tokens = tokenBudget;
        if (opts.json) body.response_format = { type: "json_object" };
        const res = await fetch(`${config.zg.baseUrl}/chat/completions`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.zg.apiKey}` },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        if (!res.ok) {
          const txt = await res.text().catch(() => "");
          const e: any = new Error(`0G ${res.status}: ${txt.slice(0, 300)}`);
          e.status = res.status;
          throw e;
        }
        const json: any = await res.json();
        const msg = json?.choices?.[0]?.message ?? {};
        const answer = (msg.content && msg.content.trim()) || "";
        // Thinking-by-default models (glm-*, minimax, qwen) can spend the ENTIRE token budget in
        // `reasoning_content` and return an empty `content`. Falling straight through to the reasoning
        // text ships the model's scratchpad to a paying caller as if it were the answer — measured:
        // asking for "FALLBACK_OK" returned "The user is asking me to reply". The cause is a budget too
        // small to leave room for an answer after the thinking, so raise it and ask once more; the
        // scratchpad is only ever used if that also comes back empty.
        if (!answer && msg.reasoning_content && !escalated) {
          escalated = true;
          tokenBudget = Math.max(1024, (tokenBudget ?? 512) * 4);
          clearTimeout(timeout);
          continue; // same model, room to actually answer this time
        }
        const raw = answer || msg.reasoning_content || "";
        const trace = json?.x_0g_trace ?? {};
        return { content: stripThink(raw), model, usage: json?.usage, costWei: trace?.billing?.total_cost, teeVerified: false, provider: trace?.provider };
      } catch (e: any) {
        lastErr = e;
        if (attempt < MAX_ATTEMPTS - 1 && isTransient(e?.status ?? null, e)) {
          await sleep(400 * 2 ** attempt + Math.floor(Math.random() * 250)); // 0.4s → 0.8s → 1.6s + jitter
          continue;
        }
        // The model itself is unusable (gated/unknown): stop retrying it and try the next candidate.
        // Any other permanent error is the request's fault and would fail identically elsewhere.
        if (isModelUnavailable(e?.status ?? null, e)) break;
        throw e;
      } finally {
        clearTimeout(timeout);
      }
    }
    }
    throw lastErr;
  } finally {
    release();
  }
}

/** Chat that must return valid JSON matching a shape; retries once on parse failure. */
export async function chatJson<T = any>(
  messages: ChatMsg[],
  opts: { tier?: ModelTier; temperature?: number; maxTokens?: number; timeoutMs?: number } = {}
): Promise<{ data: T; model: string }> {
  let lastContent = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    const { content, model } = await chat(messages, opts); // no response_format — some 0G models return empty with it
    lastContent = content;
    const parsed = extractJson(content);
    if (parsed !== undefined) return { data: parsed as T, model };
    messages = [...messages, { role: "user", content: "Return ONLY the JSON object, starting with { and ending with }." }];
  }
  throw new Error("0G returned non-JSON after retry: " + lastContent.slice(0, 200));
}

/** Extract the first balanced JSON object from arbitrary model text (handles prose/fences). */
function extractJson(s: string): unknown | undefined {
  const t = s.trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
  try { return JSON.parse(t); } catch { /* find embedded */ }
  const start = t.indexOf("{");
  if (start < 0) return undefined;
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < t.length; i++) {
    const c = t[i]!;
    if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { try { return JSON.parse(t.slice(start, i + 1)); } catch { return undefined; } } }
  }
  return undefined;
}

/** Parallel jury: same prompt across N diverse models; returns all answers for aggregation. */
export async function jury(
  messages: ChatMsg[],
  tiers: ModelTier[] = ["strong", "alt", "reasoning"],
  opts: { temperature?: number; maxTokens?: number } = {}
): Promise<Array<{ tier: ModelTier; content: string; model: string }>> {
  const results = await Promise.allSettled(
    tiers.map((tier) => chat(messages, { ...opts, tier }).then((r) => ({ tier, content: r.content, model: r.model })))
  );
  return results.filter((r): r is PromiseFulfilledResult<any> => r.status === "fulfilled").map((r) => r.value);
}

/** Diverse jury pool — five DIFFERENT model families (MiniMax, Zhipu, DeepSeek, Alibaba, Moonshot).
 *  Diversity is the point (Mira pattern): different architectures balance each other's biases, and
 *  consensus across families filters hallucination far better than one model repeated. No Claude
 *  (too expensive for high-frequency verification). */
export const JURY_MODELS = ["minimax-m3", "glm-5.2", "deepseek-v4-pro", "qwen3.7-max", "kimi-k2.7-code"];

export type JuryVote = { model: string; label: string; confidence: number; reason: string };
export type JuryVerdict = { label: string; confidence: number; agreement: number; votes: JuryVote[]; responded: number };

/**
 * Mira-style multi-model consensus vote. Each diverse model independently returns a JSON vote
 * {label ∈ labels, confidence 0-1, reason}. We aggregate to the modal label, agreement (share of
 * jurors on it), and confidence (mean of the agreeing jurors). Fails soft: uses whoever responds;
 * <2 responses or weak agreement is reported honestly so the caller can abstain.
 */
export async function juryConsensus(
  system: string,
  user: string,
  labels: string[],
  opts: { models?: string[]; maxTokens?: number; temperature?: number } = {}
): Promise<JuryVerdict> {
  const models = opts.models ?? JURY_MODELS;
  const sys = `${system}\n\nReturn ONLY compact JSON: {"label": one of ${JSON.stringify(labels)}, "confidence": 0.0-1.0, "reason": "<=20 words"}. No prose, no markdown.`;
  const settled = await Promise.allSettled(
    models.map(async (model): Promise<JuryVote> => {
      const { content } = await chat([{ role: "system", content: sys }, { role: "user", content: user }], {
        model, temperature: opts.temperature ?? 0.2, maxTokens: opts.maxTokens ?? 1400, // thinking models need ample room to finish reasoning THEN emit JSON
      });
      const j = extractJson(content) as any;
      // A model that didn't return a usable vote is EXCLUDED (throws), not counted as an abstention —
      // a parse failure must not masquerade as a confident vote and skew the consensus.
      if (!j || !labels.includes(j.label)) throw new Error(`${model}: no valid vote`);
      const confidence = Math.max(0, Math.min(1, Number(j.confidence) || 0.5));
      return { model, label: j.label, confidence, reason: String(j.reason ?? "").slice(0, 160) };
    })
  );
  const votes = settled.filter((r): r is PromiseFulfilledResult<JuryVote> => r.status === "fulfilled").map((r) => r.value);
  if (votes.length === 0) return { label: labels[labels.length - 1]!, confidence: 0, agreement: 0, votes: [], responded: 0 };
  const tally = new Map<string, JuryVote[]>();
  for (const v of votes) (tally.get(v.label) ?? tally.set(v.label, []).get(v.label)!).push(v);
  const [label, group] = [...tally.entries()].sort((a, b) => b[1].length - a[1].length)[0]!;
  const agreement = group.length / votes.length;
  const confidence = Number((group.reduce((s, v) => s + v.confidence, 0) / group.length * agreement).toFixed(2));
  return { label, confidence, agreement: Number(agreement.toFixed(2)), votes, responded: votes.length };
}
