import { ghJson, parseRepo } from "./gh.js";
import { chat } from "../ai/router.js";
import { RepoRadarReport, RepoSignals, type RepoGrade } from "./types.js";

/**
 * RepoRadar — GitHub due diligence from cheap `gh`-API signals (no cloning / no compiler; that's a
 * separate premium tier). Answers LEGIT / COSMETIC / RED_FLAG: is this repo real, sustained work by a
 * real team, a thin cosmetic shell, or carrying scam-signal patterns (fake stars, one-dump history,
 * abandoned)? Deterministic scorer (unit-tested) + a 0G read of README claims vs apparent code.
 */

type Reason = { severity: 1 | 2 | 3 | 4 | 5; code: string; detail: string };

/** Pure scorer: signals → grade + score + reasons (deterministic, unit-testable). */
export function scoreRepo(s: RepoSignals): { grade: RepoGrade; score: number; reasons: Reason[] } {
  const reasons: Reason[] = [];
  let score = 100;
  const hit = (sev: 1 | 2 | 3 | 4 | 5, code: string, detail: string, penalty: number) => { reasons.push({ severity: sev, code, detail }); score -= penalty; };
  let hardRed = false;

  // --- fake-star / bot signals ---
  if (s.stars >= 500 && s.contributors <= 1) { hit(5, "stars_without_contributors", `${s.stars.toLocaleString()} stars but only ${s.contributors} contributor — classic star-botting pattern.`, 55); hardRed = true; }
  else if (s.starsPerContributor >= 3000 && s.contributors <= 2) { hit(4, "star_contributor_imbalance", `${Math.round(s.starsPerContributor).toLocaleString()} stars per contributor — implausible without inorganic stars.`, 35); }
  if (s.ageDays < 30 && s.stars >= 1000 && s.commitsSampled <= 5) { hit(5, "young_hyped_empty", `${s.stars.toLocaleString()} stars on a ${Math.round(s.ageDays)}-day-old repo with almost no commits — velocity looks manufactured.`, 50); hardRed = true; }

  // --- cosmetic / thin signals ---
  if (s.distinctAuthors <= 1 && s.commitSpanDays < 2 && s.commitsSampled >= 5) { hit(3, "single_dump_history", `All ${s.commitsSampled} sampled commits are one author within ${s.commitSpanDays.toFixed(1)} days — a code dump, not organic development.`, 25); }
  if (!s.hasTests) hit(2, "no_tests", "No test files found — unverified quality for a project claiming to be usable.", 12);
  if (!s.hasCI) hit(1, "no_ci", "No CI workflows — nothing automatically checks the code.", 6);
  if (!s.hasLicense) hit(1, "no_license", "No license file.", 4);
  if (s.readmeLength < 200) hit(2, "thin_readme", `README is only ${s.readmeLength} chars — little documentation.`, 10);
  if (s.topContributorShare >= 0.95 && s.contributors > 1) hit(2, "bus_factor_one", `One author wrote ${(s.topContributorShare * 100).toFixed(0)}% of commits — single point of failure.`, 8);

  // --- health / staleness ---
  if (s.isArchived) hit(3, "archived", "Repository is archived (read-only / no longer maintained).", 15);
  if (s.lastPushDays > 365) hit(2, "stale", `No push in ${Math.round(s.lastPushDays)} days — likely abandoned.`, 10);
  if (s.isFork) hit(1, "is_fork", "This is a fork — verify it is not fork-farming to inflate a network.", 5);

  // positives (don't add above 100, but note strength)
  if (s.contributors >= 10 && s.hasTests && s.hasCI) reasons.push({ severity: 1, code: "healthy_project", detail: `${s.contributors}+ contributors with tests and CI — signs of a real, maintained project.` });

  score = Math.max(0, Math.min(100, Math.round(score)));
  let grade: RepoGrade = score >= 70 ? "LEGIT" : score >= 40 ? "COSMETIC" : "RED_FLAG";
  if (hardRed) grade = "RED_FLAG";
  reasons.sort((a, b) => b.severity - a.severity);
  return { grade, score, reasons };
}

const days = (iso: string | null | undefined): number => (iso ? (Date.now() - new Date(iso).getTime()) / 86_400_000 : 0);

const TEST_RE = /(^|\/)(tests?|__tests__|spec|specs)(\/|$)|\.(test|spec)\.[a-z]+$/i;

export async function repoRadar(input: string): Promise<RepoRadarReport> {
  const observed_at = new Date().toISOString();
  const full = parseRepo(input);
  const base = { ok: false, repo: input, observed_at, grade: "COSMETIC" as RepoGrade, score: 50, confidence: 0.2, summary: "", reasons: [] as any[], signals: null, claims_check: null, disclaimer: "Metadata due-diligence only. Not a code audit; deep static analysis is a separate tier." };
  if (!full) return RepoRadarReport.parse({ ...base, error: "could not parse a github owner/repo from input" });

  const [repo, contributors, commits, tree, readme] = await Promise.all([
    ghJson(`repos/${full}`),
    ghJson(`repos/${full}/contributors?per_page=100&anon=false`),
    ghJson(`repos/${full}/commits?per_page=30`),
    ghJson(`repos/${full}/git/trees/HEAD?recursive=1`),
    ghJson(`repos/${full}/readme`),
  ]);
  if (!repo || repo.message) return RepoRadarReport.parse({ ...base, error: repo?.message ?? "repo not found, private, or GitHub API rate-limited" });

  const contribArr: any[] = Array.isArray(contributors) ? contributors : [];
  const totalContribCommits = contribArr.reduce((n, c) => n + (c.contributions || 0), 0);
  const topShare = totalContribCommits > 0 ? (contribArr[0]?.contributions || 0) / totalContribCommits : 0;

  const commitArr: any[] = Array.isArray(commits) ? commits : [];
  const authorSet = new Set(commitArr.map((c) => c.author?.login || c.commit?.author?.email).filter(Boolean));
  const commitDates = commitArr.map((c) => new Date(c.commit?.author?.date ?? c.commit?.committer?.date ?? Date.now()).getTime()).filter((n) => n > 0);
  const commitSpanDays = commitDates.length >= 2 ? (Math.max(...commitDates) - Math.min(...commitDates)) / 86_400_000 : 0;

  const paths: string[] = Array.isArray(tree?.tree) ? tree.tree.map((t: any) => t.path as string) : [];
  const hasTests = paths.some((p) => TEST_RE.test(p));
  const hasCI = paths.some((p) => p.startsWith(".github/workflows/"));
  const hasLicense = !!repo.license || paths.some((p) => /^licen[cs]e/i.test(p));
  const hasReadme = !!readme?.content || paths.some((p) => /^readme/i.test(p));
  const readmeText = readme?.content ? Buffer.from(readme.content, "base64").toString("utf8") : "";

  const ageDays = days(repo.created_at);
  const signals = RepoSignals.parse({
    fullName: repo.full_name ?? full,
    stars: repo.stargazers_count ?? 0,
    forks: repo.forks_count ?? 0,
    ageDays,
    lastPushDays: days(repo.pushed_at),
    contributors: contribArr.length,
    topContributorShare: topShare,
    commitsSampled: commitArr.length,
    distinctAuthors: authorSet.size,
    commitSpanDays,
    openIssues: repo.open_issues_count ?? 0,
    isFork: !!repo.fork,
    isArchived: !!repo.archived,
    hasTests, hasCI, hasLicense, hasReadme,
    readmeLength: readmeText.length,
    starsPerContributor: (repo.stargazers_count ?? 0) / Math.max(1, contribArr.length),
    starsPerDay: (repo.stargazers_count ?? 0) / Math.max(1, ageDays),
  });

  const { grade, score, reasons } = scoreRepo(signals);

  // claims-vs-code read + summary (0G decentralized compute)
  let claims_check: string | null = null;
  let summary = "";
  let attestation: { tee_verified: boolean; provider?: string; model?: string } | null = null;
  try {
    const facts = reasons.map((r) => `- [sev${r.severity}] ${r.code}: ${r.detail}`).join("\n");
    const r = await chat(
      [
        { role: "system", content: "You are RepoRadar doing GitHub due diligence. Given metadata signals and the README, write (a) a 2-sentence verdict summary and (b) a one-sentence claims_check: do the README's claims (e.g. 'audited', 'production', 'on-chain', 'AI') look backed by the repo's apparent activity/structure, or unsupported? Use ONLY the provided data. Be direct. Return ONLY JSON {\"summary\":\"...\",\"claims_check\":\"...\"}." },
        { role: "user", content: `Repo: ${signals.fullName} — grade ${grade} (${score}/100)\nSignals:\n${facts}\n\nREADME (first 1500 chars):\n${readmeText.slice(0, 1500)}` },
      ],
      { tier: "strong", maxTokens: 400, temperature: 0.2, verifyTee: true }
    );
    attestation = { tee_verified: r.teeVerified === true, provider: r.provider, model: r.model };
    const data = parseJson(r.content) ?? {};
    summary = String(data.summary ?? "").slice(0, 400);
    claims_check = data.claims_check ? String(data.claims_check).slice(0, 300) : null;
  } catch { /* deterministic fallback below */ }
  if (!summary) summary = `${signals.fullName} graded ${grade} (${score}/100). ${reasons.slice(0, 2).map((r) => r.detail).join(" ")}`;

  return RepoRadarReport.parse({
    ok: true, repo: signals.fullName, observed_at, grade, score,
    confidence: Math.min(0.9, 0.5 + (commitArr.length / 60) + (contribArr.length > 0 ? 0.15 : 0)),
    summary, reasons, signals, claims_check, attestation,
    disclaimer: base.disclaimer,
  });
}

function parseJson(s: string): any | undefined {
  const t = s.trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```$/i, "").trim();
  try { return JSON.parse(t); } catch {}
  const a = t.indexOf("{"), b = t.lastIndexOf("}");
  if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch {} }
  return undefined;
}
