import { createHash } from "node:crypto";
import type { ChainKey } from "../config.js";
import { preTxGuardian } from "./pretx.js";
import { checkCounterparty } from "./counterparty.js";
import { scanContent } from "./promptfw.js";
import { scamSignals } from "../engine/check.js";
import { htmlToText } from "../evidence/prove.js";
import { safeFetch } from "../net/safeFetch.js";

/**
 * ActionGuard — the umbrella call an agent makes BEFORE it acts. It composes Aletheia's pre-action checks
 * (transaction guardian + counterparty + prompt firewall + data-loss prevention) into ONE decision:
 * ALLOW / REVIEW / BLOCK, with every sub-check's evidence and a hashed decision trace (auditable, and
 * committable on-chain via the registry). Worst sub-decision wins — safety-first composition. Per-call ASP.
 */

export type ActionDecision = "ALLOW" | "REVIEW" | "BLOCK";
type Action =
  | { type: "transaction"; chain: ChainKey; to: string; data?: string; value?: string; payload?: string }
  | { type: "content"; content?: string; url?: string }
  | { type: "counterparty"; chain: ChainKey; address: string };

export type ActionGuardResult = {
  ok: boolean;
  observed_at: string;
  action_type: string;
  decision: ActionDecision;
  checks: { name: string; decision: ActionDecision; detail: string }[];
  dlp: { leaked: boolean; kinds: string[] };
  reasons: string[];
  trace_id: string; // sha256 of the decision record — the signed trace anchor
  summary: string;
  error?: string;
};

import { BIP39 } from "./bip39.js";

const sev = (d: ActionDecision): number => (d === "ALLOW" ? 0 : d === "REVIEW" ? 1 : 2);
const worst = (a: ActionDecision, b: ActionDecision): ActionDecision => (sev(a) >= sev(b) ? a : b);

// Data-loss prevention: patterns for secrets that must never leave in an outbound payload.
const DLP_RULES: { kind: string; re: RegExp }[] = [
  { kind: "evm_private_key", re: /\b0x[a-fA-F0-9]{64}\b/ },
  { kind: "api_key", re: /\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{30,})\b/ },
  { kind: "aws_secret", re: /aws_secret_access_key\s*[=:]\s*\S+/i },
];

/** A mnemonic is 12+ CONSECUTIVE words that are all in the BIP-39 wordlist — not just any run of short
 *  words (which would false-flag ordinary prose). Real seed phrases are 12/15/18/21/24 BIP-39 words. */
function hasSeedPhrase(payload: string): boolean {
  const words = (payload || "").toLowerCase().match(/[a-z]+/g) || [];
  let run = 0;
  for (const w of words) {
    if (BIP39.has(w)) { if (++run >= 12) return true; } else run = 0;
  }
  return false;
}

/** Scan an outbound payload for secrets that shouldn't leave (pure, testable). */
export function dlpScan(payload: string): { leaked: boolean; kinds: string[] } {
  const kinds = DLP_RULES.filter((r) => r.re.test(payload || "")).map((r) => r.kind);
  if (hasSeedPhrase(payload)) kinds.push("seed_phrase");
  return { leaked: kinds.length > 0, kinds: [...new Set(kinds)] };
}

export async function actionGuard(action: Action): Promise<ActionGuardResult> {
  const observed_at = new Date().toISOString();
  const checks: ActionGuardResult["checks"] = [];
  const reasons: string[] = [];
  let decision: ActionDecision = "ALLOW";
  let dlp = { leaked: false, kinds: [] as string[] };

  try {
    if (action.type === "transaction") {
      const [tx, cp] = await Promise.all([
        preTxGuardian(action.chain, { to: action.to, data: action.data, value: action.value }),
        checkCounterparty(action.chain, action.to),
      ]);
      checks.push({ name: "tx_guardian", decision: tx.decision, detail: tx.summary });
      const cpDec: ActionDecision = cp.verdict === "FLAGGED" ? "BLOCK" : cp.verdict === "THIN" ? "REVIEW" : "ALLOW";
      checks.push({ name: "counterparty", decision: cpDec, detail: cp.summary });
      decision = worst(tx.decision, cpDec);
      reasons.push(...tx.expected_changes, ...cp.reasons);
      dlp = dlpScan(action.payload ?? action.data ?? "");
    } else if (action.type === "content") {
      let content = action.content ?? "";
      if (!content && action.url) {
        // SSRF-guarded fetch — an internal/metadata URL is blocked and simply yields no content.
        try { const r = await safeFetch(action.url, { maxBytes: 1_000_000, timeoutMs: 15_000 }); content = htmlToText(r.text); } catch { /* unreachable or blocked → treat as no content */ }
      }
      const fw = scanContent(content);
      const fwDec: ActionDecision = fw.verdict === "INJECTION" ? "BLOCK" : fw.verdict === "SUSPICIOUS" ? "REVIEW" : "ALLOW";
      checks.push({ name: "prompt_firewall", decision: fwDec, detail: fw.summary });
      // The scam scan was already written, already good, and simply never called from here.
      //
      // A textbook drainer lure — "your wallet is flagged, enter your 12-word seed phrase at
      // okx-wallet-recovery… within 30 minutes or your balance will be frozen" — came back REVIEW,
      // with `urgency_coercion` as the only signal. The prompt firewall was the sole check on this
      // path, and a phishing message aimed at a human is not a prompt injection, so it saw only the
      // pressure tactic and missed the seed-phrase ask entirely. For a product sold as the one gate
      // an agent passes through before it acts, the most unambiguous BLOCK in crypto returning
      // "needs a second look" is the wrong answer.
      //
      // `scamSignals` scores that same text `high` on its first rule. /check has been calling it all
      // along; ActionGuard had not.
      const scam = scamSignals(content);
      const scamDec: ActionDecision = scam.severity === "high" ? "BLOCK" : scam.severity === "medium" ? "REVIEW" : "ALLOW";
      checks.push({
        name: "scam_signals",
        decision: scamDec,
        detail: scam.flags.length ? `${scam.severity.toUpperCase()} — ${scam.flags.join("; ")}.` : "No scam/phishing patterns detected.",
      });
      decision = worst(fwDec, scamDec);
      reasons.push(...fw.hits.map((h) => `${h.category}: ${h.detail}`), ...scam.flags);
      dlp = dlpScan(content);
    } else if (action.type === "counterparty") {
      const cp = await checkCounterparty(action.chain, action.address);
      const cpDec: ActionDecision = cp.verdict === "FLAGGED" ? "BLOCK" : cp.verdict === "THIN" ? "REVIEW" : "ALLOW";
      checks.push({ name: "counterparty", decision: cpDec, detail: cp.summary });
      decision = cpDec;
      reasons.push(...cp.reasons);
    }

    // DLP is a hard override — secrets leaving is always a BLOCK.
    if (dlp.leaked) {
      checks.push({ name: "dlp", decision: "BLOCK", detail: `Outbound payload contains secrets: ${dlp.kinds.join(", ")}.` });
      decision = "BLOCK";
      reasons.unshift(`Data-loss prevention: the action would leak ${dlp.kinds.join(", ")}.`);
    }

    const record = { action_type: action.type, decision, checks, observed_at };
    const trace_id = createHash("sha256").update(JSON.stringify(record)).digest("hex");
    const summary =
      decision === "BLOCK" ? `BLOCK — ${checks.filter((c) => c.decision === "BLOCK").map((c) => c.name).join(", ")} flagged this action.` :
      decision === "REVIEW" ? `REVIEW — ${checks.filter((c) => c.decision === "REVIEW").map((c) => c.name).join(", ")} need a human/second look before proceeding.` :
      "ALLOW — all pre-action checks passed.";
    return { ok: true, observed_at, action_type: action.type, decision, checks, dlp, reasons: reasons.slice(0, 10), trace_id, summary };
  } catch (e: any) {
    return { ok: false, observed_at, action_type: action.type, decision: "REVIEW", checks, dlp, reasons, trace_id: "", summary: "ActionGuard check failed — do not assume safe.", error: e?.message ?? String(e) };
  }
}
