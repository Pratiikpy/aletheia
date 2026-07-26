/**
 * The thing AgentAudit probes: any OpenAI-compatible chat endpoint (an agent/ASP's LLM surface).
 * This is the common denominator across OKX.AI agents, 0G, OpenAI, and most LLM-backed services.
 * The client is dumb on purpose — it sends messages and measures latency + token usage per call, so
 * the auditor can score behavior (injection, accuracy) and performance (latency, cost) from real calls.
 */

export type TargetSpec = {
  baseUrl: string; // e.g. https://router-api.0g.ai/v1  (we append /chat/completions)
  model: string;
  apiKey?: string; // sent as Bearer if present
  headers?: Record<string, string>;
  timeoutMs?: number;
  system?: string; // optional system prompt the target is meant to run under (probed for leakage)
};

export type AskResult = {
  ok: boolean;
  content: string;
  latencyMs: number;
  promptTokens: number | null;
  completionTokens: number | null;
  status: number | null;
  error?: string;
};

type Msg = { role: "system" | "user" | "assistant"; content: string };

import { assertUrlAllowed, SsrfError } from "../net/safeFetch.js";

/** One call to the target. Never throws — failures come back as ok:false so a probe can grade them. */
export async function ask(target: TargetSpec, messages: Msg[]): Promise<AskResult> {
  // Accept both a base URL (…/v1) and a full endpoint (…/v1/chat/completions) — only append the path
  // when it isn't already there, so a caller passing the complete URL doesn't get a double-appended 404.
  const base = target.baseUrl.replace(/\/+$/, "");
  const url = /\/chat\/completions$/.test(base) ? base : base + "/chat/completions";
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), target.timeoutMs ?? 45_000);
  const started = Date.now();
  try {
    await assertUrlAllowed(url); // block auditing internal/loopback/metadata targets (SSRF)
    const headers: Record<string, string> = { "Content-Type": "application/json", ...(target.headers ?? {}) };
    if (target.apiKey) headers.Authorization = `Bearer ${target.apiKey}`;
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ model: target.model, messages, temperature: 0 }),
      signal: controller.signal,
    });
    const latencyMs = Date.now() - started;
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      return { ok: false, content: "", latencyMs, promptTokens: null, completionTokens: null, status: res.status, error: `${res.status}: ${txt.slice(0, 200)}` };
    }
    const json: any = await res.json();
    const msg = json?.choices?.[0]?.message ?? {};
    const content = (typeof msg.content === "string" && msg.content) || msg.reasoning_content || "";
    const usage = json?.usage ?? {};
    return {
      ok: true,
      content: String(content),
      latencyMs,
      promptTokens: num(usage.prompt_tokens),
      completionTokens: num(usage.completion_tokens),
      status: res.status,
    };
  } catch (e: any) {
    const latencyMs = Date.now() - started;
    const aborted = e?.name === "AbortError";
    return { ok: false, content: "", latencyMs, promptTokens: null, completionTokens: null, status: null, error: aborted ? "timeout" : e?.message ?? String(e) };
  } finally {
    clearTimeout(timeout);
  }
}

function num(v: any): number | null {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** Build the message list for a probe, prepending the target's declared system prompt if any. */
export function withSystem(target: TargetSpec, userPrompt: string, extraSystem?: string): Msg[] {
  const sys = [target.system, extraSystem].filter(Boolean).join("\n\n");
  const msgs: Msg[] = [];
  if (sys) msgs.push({ role: "system", content: sys });
  msgs.push({ role: "user", content: userPrompt });
  return msgs;
}
