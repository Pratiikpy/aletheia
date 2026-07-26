/**
 * Prompt Firewall — scan retrieved/untrusted content (a web page, a document, an MCP tool result)
 * for prompt-injection / jailbreak attempts BEFORE an agent follows it. Input-side counterpart to
 * AgentAudit's output-side probes.
 *
 * Signature battery synthesized from the open-source state of the art — NVIDIA/garak probe families
 * (dan, grandma, promptinject, latentinjection, encoding, leakreplay, exploitation), protectai/rebuff
 * heuristics, and the agent-threat-rules taxonomy — plus structural checks (invisible-unicode
 * smuggling, fake-turn stuffing) that regex alone misses. Every hit carries the matched pattern as
 * evidence, so the SAFE / SUSPICIOUS / INJECTION verdict is explainable, reproducible, and unit-testable.
 */

export type FirewallHit = { category: string; severity: 1 | 2 | 3 | 4 | 5; detail: string; match: string };
export type PromptScanResult = {
  verdict: "SAFE" | "SUSPICIOUS" | "INJECTION";
  score: number; // 0..100 risk
  hits: FirewallHit[];
  families: string[]; // distinct attack families detected
  summary: string;
};

type Rule = { category: string; severity: 1 | 2 | 3 | 4 | 5; re: RegExp; detail: string };

const RULES: Rule[] = [
  // ── core instruction subversion ──
  { category: "instruction_override", severity: 5, re: /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,28}\b(instructions?|rules?|prompt|context|guidelines?|directives?|restrictions?|constraints?|policy|policies)\b/i, detail: "tells the agent to ignore its own instructions" },
  { category: "system_prompt_exfil", severity: 5, re: /\b(reveal|repeat|print|show|output|expose|leak|display|recite)\b[^.\n]{0,40}\b(system\s?prompt|your\s+(instructions?|rules?|config|guidelines?)|everything\s+above|initial\s+prompt|the\s+text\s+above)\b/i, detail: "tries to make the agent leak its system prompt" },
  { category: "prompt_leak_probe", severity: 4, re: /\b(what\s+(are|were)\s+your\s+(instructions|rules|guidelines|directives)|repeat\s+the\s+(words?|text)\s+above|print\s+your\s+(prompt|configuration))\b/i, detail: "probes to extract the agent's hidden prompt" },
  { category: "role_hijack", severity: 4, re: /\byou\s+are\s+now\b|\bact\s+as\b[^.\n]{0,30}\b(DAN|jailbroken|unrestricted|no\s+restrictions?|developer\s+mode|evil|amoral)\b|\bpretend\s+you\s+(are|have|can)\b|\bfrom\s+now\s+on\s+you\b/i, detail: "reassigns the agent's role/persona" },
  // ── known jailbreak personas (garak: dan) ──
  { category: "dan_jailbreak", severity: 4, re: /\b(DAN|do\s+anything\s+now|AIM\b|STAN\b|DUDE\b|Mongo\s+Tom|Machiavelli|jailbreak(en|ed)?|developer\s+mode\s+(enabled|on)|\bAntiGPT\b)\b|🔓|\[?JAILBREAK\]?/i, detail: "invokes a known jailbreak persona/token" },
  { category: "grandma_exploit", severity: 3, re: /\b(grand\s?ma|grand\s?mother|deceased|late)\b[^.\n]{0,45}\b(used\s+to|would|tell|read|recipe|bedtime|whisper|sing)\b/i, detail: "grandma/roleplay exploit to smuggle a request" },
  // ── obedience coercion ──
  { category: "override_refusal", severity: 3, re: /\b(never|do\s?n['o]?t|no\s+need\s+to)\b[^.\n]{0,25}\b(refuse|decline|warn|apologi[sz]e|say\s+you\s+can'?t|add\s+a\s+disclaimer)\b|\balways\s+comply\b|\bwithout\s+(any\s+)?(warning|refusal|caveat)\b/i, detail: "suppresses the agent's refusals/warnings" },
  { category: "authority_spoof", severity: 4, re: /\b(as\s+(your|the)\s+(admin(istrator)?|developer|owner|operator|creator|OpenAI|Anthropic|system)|official\s+system\s+(message|update)|authorized\s+(by|override)|this\s+is\s+(your\s+)?(developer|admin))\b/i, detail: "spoofs authority (admin/developer/system) to gain compliance" },
  { category: "urgency_coercion", severity: 3, re: /\b(URGENT|immediately\s+you\s+must|you\s+(will|are\s+going\s+to)\s+be\s+(shut\s+down|deleted|terminated|penali[sz]ed)|or\s+else|failure\s+to\s+comply|you\s+have\s+no\s+choice)\b/i, detail: "uses urgency/threat to coerce action" },
  { category: "reward_bait", severity: 2, re: /\b(you'?ll\s+be\s+rewarded|good\s+(bot|assistant|ai)|earn\s+\d+\s+(points?|tokens?)|stay\s+in\s+character|remain\s+in\s+character)\b/i, detail: "bribes/rewards the agent to break rules" },
  // ── exfiltration & actions ──
  { category: "tool_exfil", severity: 5, re: /\b(send|post|email|upload|exfiltrate|forward|leak|dm)\b[^.\n]{0,45}\b(secret|api\s?key|private\s?key|seed\s?phrase|password|credential|env|token|mnemonic)\b[^.\n]{0,45}\b(to|http|@|address)\b/i, detail: "instructs the agent to exfiltrate secrets" },
  { category: "data_exfil_link", severity: 5, re: /!\[[^\]]*\]\(https?:\/\/[^)]*[?&](q|data|content|prompt|leak|text|s)=|\[[^\]]*\]\(https?:\/\/[^)]*[?&](q|data|prompt)=/i, detail: "markdown image/link that exfiltrates data via URL params" },
  { category: "action_injection", severity: 4, re: /\b(approve|transfer|send|sign|swap|withdraw|drain|delegate|setApprovalForAll|move)\b[^.\n]{0,30}\b(all|entire|max|unlimited|every|the)\b[^.\n]{0,20}\b(funds?|balance|tokens?|wallet|assets?|treasury|coins?|crypto|money)\b/i, detail: "instructs the agent to perform a draining financial action" },
  { category: "action_injection", severity: 4, re: /\b(transfer|send|move|withdraw|drain|forward|wire)\b[^.\n]{0,40}\bto\b\s*(0x[a-fA-F0-9]{6,}|the\s+address|this\s+(address|wallet)|my\s+wallet)/i, detail: "instructs the agent to send funds to a specified address" },
  { category: "code_execution", severity: 4, re: /\b(execute|run|eval|exec)\b[^.\n]{0,20}\b(the\s+following|this|below)\b[^.\n]{0,20}\b(code|command|script|shell|python|bash|payload)\b|\bos\.system\b|\bsubprocess\b/i, detail: "instructs the agent to run code/commands" },
  // ── obfuscation & indirection (garak: encoding, latentinjection) ──
  { category: "encoded_payload", severity: 3, re: /\b(base64|rot13|hex|binary|morse|leet\s?speak|caesar|unicode\s+escape)\b[^.\n]{0,40}\b(decode|decrypt|execute|run|obey|follow)\b|\b(decode|decrypt)\b[^.\n]{0,30}\b(base64|rot13|hex|binary|morse|caesar)\b/i, detail: "asks the agent to decode-and-execute a hidden payload" },
  { category: "payload_splitting", severity: 3, re: /\b(combine|concatenate|join|assemble)\b[^.\n]{0,30}\b(parts?|pieces?|following|strings?|letters?)\b|\bpart\s?\d\s?[:=]|\bstep\s?\d\s?:\s*[a-z]{1,3}\b/i, detail: "splits a malicious instruction across parts to evade filters" },
  { category: "translation_evasion", severity: 2, re: /\b(translate|respond\s+in|answer\s+in)\b[^.\n]{0,25}\b(base64|rot13|pig\s+latin|leet|morse)\b/i, detail: "uses a translation/encoding channel to evade filters" },
  // ── embedded / hidden directives ──
  { category: "embedded_system_directive", severity: 5, re: /(^|\n|<!--|\[|\{)\s*(system|assistant|developer)\s*[:>\]}]|\b(SYSTEM|ASSISTANT)\s+(MESSAGE|OVERRIDE|PROMPT)\b/im, detail: "embeds a fake system/assistant directive" },
  { category: "fake_tool_output", severity: 4, re: /\b(TOOL_RESULT|FUNCTION_CALL|OBSERVATION|TOOL_OUTPUT)\b\s*[:=]|<\/?(tool|function)_?(call|result|output)>|"function_call"\s*:/i, detail: "forges tool/function output to steer the agent" },
  { category: "hidden_instruction", severity: 4, re: /<!--[^>]*\b(instruction|system|ignore|reply|execute|send|approve)\b[^>]*-->|\[hidden\]|\bwhite\s*text\b|display\s*:\s*none/i, detail: "hides an instruction in a comment / hidden block" },
  { category: "delimiter_injection", severity: 2, re: /(?:"""|```|-{3,}|={3,}|#{3,})[\s\S]{0,20}\b(ignore|system|instruction|now\s+you|new\s+task)\b/i, detail: "uses fenced/delimiter blocks to inject a new instruction" },
];

// invisible / bidi / zero-width unicode used to smuggle hidden instructions past humans
const INVISIBLE = /[​-‏‪-‮⁠-⁤﻿­]/;
// fake conversation turns stuffed into content (many-shot / context injection)
const TURN = /(^|\n)\s*(user|human|assistant|system|ai)\s*:/gi;

/** Scan content for injection/jailbreak attempts (pure, deterministic). */
export function scanContent(content: string): PromptScanResult {
  const text = (content || "").slice(0, 40_000);
  const hits: FirewallHit[] = [];
  for (const r of RULES) {
    const m = text.match(r.re);
    if (m) hits.push({ category: r.category, severity: r.severity, detail: r.detail, match: m[0].slice(0, 120) });
  }
  // structural: invisible-unicode smuggling
  if (INVISIBLE.test(text)) hits.push({ category: "unicode_smuggling", severity: 4, detail: "hidden zero-width / bidi characters used to smuggle instructions past humans", match: "[invisible unicode]" });
  // structural: fake-turn stuffing (>=3 injected role turns)
  const turns = (text.match(TURN) || []).length;
  if (turns >= 3) hits.push({ category: "fake_turn_stuffing", severity: 3, detail: `content injects ${turns} fake conversation turns (context/many-shot injection)`, match: "[multiple role turns]" });

  const maxSev = hits.reduce((s, h) => Math.max(s, h.severity), 0);
  const score = Math.min(100, hits.reduce((s, h) => s + h.severity * h.severity * 2, 0));
  const verdict: PromptScanResult["verdict"] = maxSev >= 4 ? "INJECTION" : maxSev >= 2 ? "SUSPICIOUS" : "SAFE";
  const families = [...new Set(hits.map((h) => h.category))];
  const summary =
    verdict === "INJECTION" ? `BLOCK — prompt-injection detected (${hits.filter((h) => h.severity >= 4).map((h) => h.category).join(", ")}). Do not let the agent follow this content.` :
    verdict === "SUSPICIOUS" ? `REVIEW — manipulation-shaped patterns present (${families.join(", ")}).` :
    "SAFE — no injection/jailbreak patterns detected.";
  return { verdict, score, hits, families, summary };
}
