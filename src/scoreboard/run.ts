import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tokenVerdict, type Tier } from "../engine/verdict.js";
import { gather } from "../engine/context.js";
import type { ChainKey } from "../config.js";

type Label = { chain: ChainKey; address: string; symbol: string; label: "clean" | "honeypot" };

/**
 * Accuracy scoreboard — the trust moat. Runs Aletheia on a labeled set and measures how often it is
 * right, plus a GoPlus baseline, so accuracy is PUBLISHED (no incumbent does this).
 * "risky" prediction = verdict AVOID or any hard-flag signal.
 */
export async function runScoreboard(tier: Tier = "flag") {
  const labels: Label[] = JSON.parse(readFileSync(new URL("../../data/labels.json", import.meta.url), "utf8"));
  const rows: any[] = [];
  let tp = 0, tn = 0, fp = 0, fn = 0;
  let gpTp = 0, gpTn = 0, gpFp = 0, gpFn = 0;

  for (const l of labels) {
    const isHoneypotLabel = l.label === "honeypot";
    try {
      const [v, ctx] = await Promise.all([tokenVerdict(l.chain, l.address, tier), gather(l.chain, l.address, { sim: false })]);
      const predictedRisky = v.verdict === "AVOID" || v.signals.some((s) => s.is_hard_flag);
      const gpRisky = ctx.goplus.data?.is_honeypot === "1";

      // confusion (positive class = honeypot/risky)
      if (isHoneypotLabel && predictedRisky) tp++;
      else if (isHoneypotLabel && !predictedRisky) fn++;
      else if (!isHoneypotLabel && predictedRisky) fp++;
      else tn++;

      if (isHoneypotLabel && gpRisky) gpTp++;
      else if (isHoneypotLabel && !gpRisky) gpFn++;
      else if (!isHoneypotLabel && gpRisky) gpFp++;
      else gpTn++;

      const correct = isHoneypotLabel === predictedRisky;
      rows.push({ symbol: l.symbol, chain: l.chain, label: l.label, verity: v.verdict, score: v.score, predictedRisky, correct, gpRisky });
      console.log(`${correct ? "✓" : "✗"} ${l.symbol.padEnd(10)} [${l.chain}] label=${l.label} → Aletheia=${v.verdict}/${v.score} risky=${predictedRisky}`);
    } catch (e: any) {
      rows.push({ symbol: l.symbol, chain: l.chain, label: l.label, error: e?.message ?? String(e) });
      console.log(`! ${l.symbol} error: ${e?.message ?? e}`);
    }
  }

  // Deterministic honeypot recall case: deploy a real honeypot on a fork and confirm we catch it.
  try {
    const { deployAndDetectHoneypot } = await import("./fixture.js");
    const fx = await deployAndDetectHoneypot();
    if (fx.detected) tp++; else fn++;
    rows.push({ symbol: "HONEYPOT-FIXTURE", chain: "ethereum", label: "honeypot", verity: fx.detected ? "AVOID" : "GO", score: fx.detected ? 5 : 90, predictedRisky: fx.detected, correct: fx.detected, gpRisky: null });
    console.log(`${fx.detected ? "✓" : "✗"} HONEYPOT-FIXTURE (deployed on fork) → detected=${fx.detected}`);
  } catch (e: any) {
    console.log("! honeypot fixture skipped:", e?.message ?? e);
  }

  const n = tp + tn + fp + fn;
  const metrics = {
    tier, n,
    verity: confusion(tp, tn, fp, fn),
    goplus_baseline: confusion(gpTp, gpTn, gpFp, gpFn),
    generated_at: new Date().toISOString(),
    note: "Positive-class honeypot RECALL is additionally validated by a deterministic on-fork honeypot fixture (scripts/test-honeypot-positive.mts). Real honeypot addresses expand this labeled set over time.",
    rows,
  };

  mkdirSync(new URL("../../data/", import.meta.url), { recursive: true });
  writeFileSync(new URL("../../data/scoreboard.json", import.meta.url), JSON.stringify(metrics, null, 2));
  writeFileSync(new URL("../../data/scoreboard.md", import.meta.url), toMarkdown(metrics));
  console.log("\n=== SCOREBOARD ===");
  console.log(`clean-set false-positive rate: ${(metrics.verity.fpr * 100).toFixed(1)}%  (Aletheia)  vs  ${(metrics.goplus_baseline.fpr * 100).toFixed(1)}%  (GoPlus is_honeypot)`);
  console.log(`accuracy: ${(metrics.verity.accuracy * 100).toFixed(1)}%   specificity: ${((metrics.verity.specificity ?? 0) * 100).toFixed(1)}%`);
  console.log("written: data/scoreboard.json + data/scoreboard.md");
  return metrics;
}

function confusion(tp: number, tn: number, fp: number, fn: number) {
  const acc = (tp + tn) / Math.max(1, tp + tn + fp + fn);
  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const recall = tp + fn === 0 ? null : tp / (tp + fn);
  const specificity = tn + fp === 0 ? null : tn / (tn + fp);
  const fpr = tn + fp === 0 ? 0 : fp / (tn + fp);
  return { tp, tn, fp, fn, accuracy: acc, precision, recall, specificity, fpr };
}

function toMarkdown(m: any): string {
  return `# Aletheia Accuracy Scoreboard\n\nGenerated ${m.generated_at} · tier=${m.tier} · n=${m.n}\n\n` +
    `| Metric | Aletheia | GoPlus baseline |\n|---|---|---|\n` +
    `| Accuracy | ${pct(m.verity.accuracy)} | ${pct(m.goplus_baseline.accuracy)} |\n` +
    `| Specificity (clean kept clean) | ${pct(m.verity.specificity)} | ${pct(m.goplus_baseline.specificity)} |\n` +
    `| False-positive rate | ${pct(m.verity.fpr)} | ${pct(m.goplus_baseline.fpr)} |\n` +
    `| Precision | ${m.verity.precision == null ? "—" : pct(m.verity.precision)} | ${m.goplus_baseline.precision == null ? "—" : pct(m.goplus_baseline.precision)} |\n` +
    `| Recall | ${m.verity.recall == null ? "—" : pct(m.verity.recall)} | ${m.goplus_baseline.recall == null ? "—" : pct(m.goplus_baseline.recall)} |\n\n` +
    `> ${m.note}\n\n## Per-token\n\n| Token | Chain | Label | Aletheia | Score | Correct |\n|---|---|---|---|---|---|\n` +
    m.rows.map((r: any) => `| ${r.symbol} | ${r.chain} | ${r.label} | ${r.verity ?? "err"} | ${r.score ?? "-"} | ${r.correct ? "✓" : r.error ? "err" : "✗"} |`).join("\n") + "\n";
}
const pct = (x: number | null) => (x == null ? "—" : (x * 100).toFixed(1) + "%");

if (import.meta.url.endsWith(process.argv[1]?.replace(/\\/g, "/").split("/").pop() ?? "")) {
  runScoreboard((process.argv[2] as Tier) ?? "flag").then(() => process.exit(0));
}
