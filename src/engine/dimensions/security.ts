import type { DimensionScore, Signal, Evidence, VerdictLabel } from "../../types/verdict.js";
import type { ChainKey } from "../../config.js";
import type { RawContext } from "../context.js";

const explorerBase: Partial<Record<ChainKey, string>> = {
  ethereum: "https://etherscan.io/address/",
  bsc: "https://bscscan.com/address/",
  base: "https://basescan.org/address/",
  arbitrum: "https://arbiscan.io/address/",
  polygon: "https://polygonscan.com/address/",
  xlayer: "https://www.oklink.com/xlayer/address/",
};

function ev(source: string, detail: string, extra: Partial<Evidence> = {}): Evidence {
  return { source, detail, observed_at: new Date().toISOString(), ...extra };
}

/**
 * Security dimension: fuses OUR multi-vector sim (measured, authoritative) with GoPlus static
 * fields (code-permitted worst-case) + RPC bytecode. Every signal carries evidence[].
 * Rule: measured beats static; the 0%-tax-but-modifiable gap is HIGH; hard flags cap the verdict.
 */
export function scoreSecurity(ctx: RawContext): DimensionScore {
  const { chain, address, goplus: gp, meta, sim, established, holderCount } = ctx;
  const freshness = new Date().toISOString();
  const addr = address.toLowerCase() as `0x${string}`;
  const explorer = explorerBase[chain] ? explorerBase[chain]! + addr : undefined;

  const g = gp.data ?? {};
  const signals: Signal[] = [];
  const yes = (v: any) => v === "1" || v === 1 || v === true;
  const cexListed = yes(g.is_in_cex) || (g.is_in_cex && g.is_in_cex.listed === "1"); // is_in_cex can be a flag or an object

  // Reputation context (computed once in gather()): for an established/trusted/CEX token, "owner can X"
  // privileges are KNOWN CENTRALIZATION (expected), not a rug trap. Fresh token → same flags are critical.
  // established → owner-privilege flags become low-severity informational notes (not hard, not AVOID).
  const centralSev = (base: 1 | 2 | 3 | 4 | 5): 1 | 2 | 3 | 4 | 5 => (established ? 1 : base);
  const centralHard = (base: boolean) => (established ? false : base);
  const centralNote = (s: string) => (established ? s + " (expected centralization for this established/CEX-listed token — not a rug indicator here)" : s);

  // ---- MEASURED (our sim) — authoritative ----
  if (sim?.simulated) {
    if (sim.isHoneypot) {
      signals.push(sig("honeypot_confirmed", 5, "security", true, 0.95,
        "Multi-vector simulation: token is buyable but EVERY sell attempt reverted across all origins — confirmed honeypot.",
        [ev("multi_vector_sim", `bought ok in ${sim.vectors.filter(v => v.boughtOk).length} vectors, sold ok in 0`, { method: "buy_sell_fork", url: explorer })]));
    } else if (sim.selectiveHoneypot) {
      signals.push(sig("selective_honeypot", 5, "security", true, 0.9,
        "Selective honeypot: some origins can sell, others cannot — classic whitelist trap.",
        [ev("multi_vector_sim", sim.vectors.map(v => `${v.label}: sold=${v.soldOk}`).join("; "), { method: "buy_sell_fork" })]));
    }
    const measuredSell = sim.maxSellTax;
    if (measuredSell != null && measuredSell >= 0.15) {
      signals.push(sig("high_sell_tax", measuredSell >= 0.5 ? 5 : 3, "security", measuredSell >= 0.5, 0.9,
        `Measured sell tax up to ${(measuredSell * 100).toFixed(1)}% in live simulation.`,
        [ev("multi_vector_sim", `maxSellTax=${(measuredSell * 100).toFixed(1)}%`, { method: "buy_sell_fork" })]));
    }
    if (sim.taxModifiableAcrossVectors) {
      signals.push(sig("tax_varies_by_origin", 4, "security", false, 0.8,
        "Sell tax differs across origins/sizes — token applies per-address or size-dependent tax (targeted trap risk).",
        [ev("multi_vector_sim", "sell-tax spread >5% across vectors", { method: "buy_sell_fork" })]));
    }
  }

  // ---- honeypot.is: CORROBORATION ONLY (never a standalone hard flag) ----
  // It is a useful independent cross-check, but it false-positives rebasing tokens (e.g. stETH), so it
  // may only STRENGTHEN a honeypot signal our own sim already found, or be noted as a discrepancy.
  const hp = ctx.hpis;
  const ourSimSaysHoneypot = sim?.simulated && (sim.isHoneypot || sim.selectiveHoneypot);
  const ourSimCleared = sim?.simulated && !sim.isHoneypot && !sim.selectiveHoneypot;
  if (hp?.ok && hp.isHoneypot === true && ourSimSaysHoneypot) {
    // agreement — add corroborating evidence to raise confidence in the (already-fired) honeypot signal.
    const target = signals.find((s) => s.code === "honeypot_confirmed" || s.code === "selective_honeypot");
    if (target) target.evidence.push(ev("honeypot.is", "independently confirms honeypot (isHoneypot=true)"));
  } else if (hp?.ok && hp.isHoneypot === true && ourSimCleared) {
    // honeypot.is flags but WE sold it fine (rebasing/edge cases like stETH) — note, never flag.
    signals.push(sig("honeypotis_discrepancy", 1, "security", false, 0.5,
      "honeypot.is flags this token, but Aletheia's own multi-vector simulation bought AND sold it successfully — likely a rebasing/edge-case false positive on their side, not a real trap.",
      [ev("honeypot.is", "isHoneypot=true — overridden by Aletheia's successful live sell simulation")]));
  }

  // ---- DEPLOYER / CREATOR FORENSICS (the #1 requested pre-trade signal) ----
  const dep = ctx.deployer;
  if (dep?.ok) {
    // Known-malicious deployer (GoPlus address-security) — hard flag regardless of token reputation.
    if (dep.maliciousFlags.length > 0) {
      signals.push(sig("malicious_deployer", 5, "security", true, 0.9,
        `The deployer address is flagged for: ${dep.maliciousFlags.join(", ").replace(/_/g, " ")}.`,
        [ev("goplus", `address-security flags on ${short(dep.creator!)}: ${dep.maliciousFlags.join(",")}`, { url: explorer })]));
    }
    // Free serial-rugger signal — GoPlus counts prior malicious contracts by this deployer.
    if (dep.maliciousContractsCreated != null && dep.maliciousContractsCreated > 0) {
      signals.push(sig("serial_malicious_deployer", 5, "security", true, 0.9,
        `This deployer has already created ${dep.maliciousContractsCreated} known-malicious contract(s) — serial scam operator.`,
        [ev("goplus", `number_of_malicious_contracts_created=${dep.maliciousContractsCreated}`, { url: explorer })]));
    }
  }
  if (dep?.ok && !established) {
    if (dep.funderIsMixer) {
      signals.push(sig("deployer_mixer_funded", 5, "security", true, 0.85,
        "The deployer wallet was funded by a mixer (Tornado Cash) — a strong indicator of a wallet hiding its identity to rug.",
        [ev("rpc", `deployer ${short(dep.creator!)} funded by mixer ${short(dep.funder!)}`, { url: explorer })]));
    }
    if (dep.txCount != null && dep.txCount <= 5) {
      signals.push(sig("fresh_throwaway_deployer", 3, "security", false, 0.75,
        `The deployer wallet is brand-new (only ${dep.txCount} transactions) — a throwaway wallet spun up to launch, typical of rug operators rather than a committed team.`,
        [ev("rpc", `deployer ${short(dep.creator!)} txCount=${dep.txCount}`, { url: explorer })]));
    }
  }
  // Serial-rugger history (OKX Onchain OS dev info) — activates with OKX creds
  const devInfo = ctx.okx?.memepump;
  const rugCount = devInfo ? Number(devInfo.devRugCount ?? devInfo.rugCount ?? devInfo.creatorRugCount) : NaN;
  const devTokens = devInfo ? Number(devInfo.devTokenCount ?? devInfo.createdTokenCount) : NaN;
  if (!Number.isNaN(rugCount) && rugCount >= 1 && !established) {
    signals.push(sig("serial_rugger", 5, "security", true, 0.85,
      `This deployer has previously launched ${rugCount} token(s) that rugged${!Number.isNaN(devTokens) ? ` (of ${devTokens} created)` : ""} — serial rug operator.`,
      [ev("okx_onchainos", `dev rug history: ${rugCount} prior rugs`, { url: explorer })]));
  }

  // ---- STATIC (GoPlus) — code-permitted worst case ----
  const measuredSellKnownSafe = sim?.simulated && sim.maxSellTax != null && sim.maxSellTax < 0.05 && !sim.isHoneypot;
  if (yes(g.is_honeypot) && !(sim?.simulated && !sim.isHoneypot)) {
    signals.push(sig("goplus_honeypot_flag", 5, "security", true, 0.7, "GoPlus flags this token as a honeypot.",
      [ev("goplus", "is_honeypot=1", { snippet: "is_honeypot=1", url: explorer })]));
  }
  // scam indicators — always hard, regardless of reputation
  if (yes(g.fake_token)) {
    signals.push(sig("counterfeit_token", 5, "security", true, 0.9, "Counterfeit of a well-known token (impersonation scam).",
      [ev("goplus", "fake_token=1", { snippet: "fake_token=1", url: explorer })]));
  }
  if (yes(g.is_airdrop_scam)) {
    signals.push(sig("airdrop_scam", 5, "security", true, 0.9, "Flagged as an airdrop scam.",
      [ev("goplus", "is_airdrop_scam=1", { snippet: "is_airdrop_scam=1", url: explorer })]));
  }

  // the 0%-now-but-modifiable gap — the single biggest miss in competitors
  if (yes(g.slippage_modifiable)) {
    signals.push(sig("unbounded_modifiable_tax", centralSev(measuredSellKnownSafe ? 4 : 3), "security", false, 0.85,
      centralNote("Owner can change the trading tax at will — current low tax can be raised to trap sellers after they buy."),
      [ev("goplus", "slippage_modifiable=1 (tax is owner-adjustable)", { snippet: "slippage_modifiable=1", url: explorer })]));
  }
  if (yes(g.personal_slippage_modifiable)) {
    signals.push(sig("per_address_tax", centralSev(4), "security", false, 0.85,
      centralNote("Owner can set a DIFFERENT tax per address — enables targeting specific wallets (selective honeypot)."),
      [ev("goplus", "personal_slippage_modifiable=1", { snippet: "personal_slippage_modifiable=1", url: explorer })]));
  }
  if (yes(g.owner_change_balance)) {
    signals.push(sig("owner_can_edit_balances", centralSev(5), "security", centralHard(true), 0.9,
      centralNote("Owner can arbitrarily rewrite any holder's balance."),
      [ev("goplus", "owner_change_balance=1", { snippet: "owner_change_balance=1", url: explorer })]));
  }
  if (yes(g.hidden_owner)) {
    signals.push(sig("hidden_owner", centralSev(4), "security", centralHard(false), 0.85,
      centralNote("Contract retains a hidden owner despite appearing renounced."),
      [ev("goplus", "hidden_owner=1", { snippet: "hidden_owner=1", url: explorer })]));
  }
  if (yes(g.can_take_back_ownership)) {
    signals.push(sig("reclaimable_ownership", centralSev(4), "security", false, 0.85,
      centralNote("Ownership can be re-claimed after renouncement (fake renounce)."),
      [ev("goplus", "can_take_back_ownership=1", { snippet: "can_take_back_ownership=1", url: explorer })]));
  }
  if (yes(g.selfdestruct)) {
    signals.push(sig("selfdestruct", centralSev(5), "security", centralHard(true), 0.9, centralNote("Contract can self-destruct."),
      [ev("goplus", "selfdestruct=1", { snippet: "selfdestruct=1", url: explorer })]));
  }
  const renounced = g.owner_address === "0x0000000000000000000000000000000000000000" || g.owner_address === "";
  if (yes(g.is_mintable) && !renounced) {
    signals.push(sig("mintable", centralSev(3), "security", false, 0.8,
      centralNote("Supply is mintable by a non-renounced owner (dilution risk)."),
      [ev("goplus", `is_mintable=1, owner=${g.owner_address}`, { snippet: "is_mintable=1", url: explorer })]));
  }
  if (established) {
    signals.push(sig("established_token", 1, "security", false, 0.9,
      `Established token — ${holderCount.toLocaleString()} holders${cexListed ? ", CEX-listed" : ""}${yes(g.trust_list) ? ", on GoPlus trust list" : ""}.`,
      [ev("goplus", `holder_count=${holderCount}, trust_list=${g.trust_list ?? 0}, is_in_cex=${cexListed ? 1 : 0}`, { url: explorer })]));
  }
  if (yes(g.is_proxy)) {
    signals.push(sig("upgradeable_proxy", 2, "security", false, 0.75, "Contract is an upgradeable proxy — logic can change after review.",
      [ev("goplus", "is_proxy=1", { snippet: "is_proxy=1", url: explorer })]));
  }
  const unverified = g.is_open_source != null && !yes(g.is_open_source);
  if (unverified) {
    signals.push(sig("unverified_source", 3, "security", false, 0.8, "Contract source is not verified — cannot audit its behavior.",
      [ev("goplus", "is_open_source=0", { snippet: "is_open_source=0", url: explorer })]));
  }

  // ---- BYTECODE TRAP-SELECTOR SCAN (works even on unverified contracts — GoPlus's blind spot) ----
  const bc = ctx.bytecode;
  if (bc?.ok && bc.isContract) {
    // The dangerous shape is an owner-controlled rug chassis: blacklist + fee-control + trading gate together.
    // On an UNVERIFIED contract this is the strongest static red flag we can raise (nobody can read the source).
    if (bc.rugChassisScore >= 1 && !established) {
      const caps = bc.capabilities.join(" + ");
      signals.push(sig("bytecode_rug_chassis", unverified ? 4 : 3, "security", centralHard(unverified), 0.75,
        `Contract bytecode exposes a full rug chassis (${caps})${unverified ? " and the source is UNVERIFIED — the exact functions used to blacklist sellers, raise tax, and gate trading are present and unauditable" : ""}.`,
        [ev("bytecode_scan", `capabilities: ${bc.capabilities.join(",")}; matched selectors: ${bc.matches.map((m) => m.signature).slice(0, 6).join(", ")}`, { method: "selector_match", url: explorer })]));
    } else if (unverified && bc.capabilities.includes("blacklist")) {
      signals.push(sig("unverified_blacklist_capability", 3, "security", false, 0.7,
        "The unverified contract's bytecode contains a blacklist function — sellers can be silently blocked and the code cannot be reviewed.",
        [ev("bytecode_scan", `blacklist selector present: ${bc.matches.filter((m) => m.capability === "blacklist").map((m) => m.signature).join(", ")}`, { method: "selector_match", url: explorer })]));
    }
  }
  // holder concentration — EXCLUDE LP pools, burn addresses, locked and contract holders (not dump risk)
  const BURN = new Set(["0x000000000000000000000000000000000000dead", "0x0000000000000000000000000000000000000000"]);
  const isNonDump = (h: any) => h.is_contract === "1" || h.is_contract === 1 || h.is_locked === true || h.is_locked === "1" || BURN.has((h.address || "").toLowerCase());
  const top = (Array.isArray(g.holders) ? g.holders : []).filter((h: any) => !isNonDump(h));
  const topPct = top.slice(0, 1).reduce((s: number, h: any) => s + (parseFloat(h.percent) || 0), 0);
  if (topPct >= 0.5) {
    signals.push(sig("holder_concentration", topPct >= 0.8 ? 4 : 3, "security", false, 0.7,
      `Top holder controls ${(topPct * 100).toFixed(1)}% of supply.`,
      [ev("goplus", `top1=${(topPct * 100).toFixed(1)}%`, { url: explorer })]));
  }
  // ---- INSIDER / SYBIL CLUSTERS (self-computed — Magic-Nodes equivalent) ----
  // Top holders linked by a shared funder or a same-block coordinated seed act as ONE effective holder.
  // Deployer-seeded float is the worst case (stealth insider allocation dressed as many small wallets).
  const cl = ctx.insiderCluster;
  if (cl?.ok && cl.clusters.length > 0) {
    const big = cl.clusters[0]!;
    if (cl.deployerSeededPercent >= 0.05) {
      signals.push(sig("deployer_seeded_cluster", 5, "security", centralHard(true), 0.8,
        `A cluster of ${big.members.length}+ wallets funded by the deployer controls ${(cl.deployerSeededPercent * 100).toFixed(1)}% of supply — stealth insider float disguised as many small holders.`,
        [ev("cluster_analysis", `deployer-funded cluster: ${big.members.length} wallets, ${(cl.deployerSeededPercent * 100).toFixed(1)}% combined`, { method: "funding_graph", url: explorer })]));
    } else if (big.combinedPercent >= 0.15) {
      signals.push(sig("insider_cluster", big.combinedPercent >= 0.30 ? 4 : 3, "security", false, 0.7,
        `${big.members.length} of the top holders are linked (${big.linkage === "common_funder" ? "same funding wallet" : "bought in the same block"}) and jointly control ${(big.combinedPercent * 100).toFixed(1)}% of supply — likely one entity, not organic distribution.`,
        [ev("cluster_analysis", `cluster anchor=${big.anchor} members=${big.members.length} combined=${(big.combinedPercent * 100).toFixed(1)}% linkage=${big.linkage}`, { method: "funding_graph", url: explorer })]));
    }
  }

  // ---- INSIDER DISTRIBUTION IN PROGRESS (flow — pairs with the static cluster map) ----
  const fl = ctx.insiderFlow;
  if (fl?.ok && fl.walletsTracked > 0) {
    if (fl.aggregateDistributedPct >= 0.3 || fl.worstDistributedPct >= 0.5) {
      signals.push(sig("insiders_distributing", fl.aggregateDistributedPct >= 0.5 ? 4 : 3, "security", false, 0.7,
        `Insiders are exiting: the deployer/insider wallets have already sent out ${(fl.aggregateDistributedPct * 100).toFixed(0)}% of the tokens they received${fl.activelyDistributing > 0 ? ` (${fl.activelyDistributing} wallet(s) actively distributing)` : ""} — distribution/exit in progress.`,
        [ev("insider_flow", `aggregate distributed=${(fl.aggregateDistributedPct * 100).toFixed(0)}%, worst wallet=${(fl.worstDistributedPct * 100).toFixed(0)}%, active=${fl.activelyDistributing}/${fl.walletsTracked}`, { method: "transfer_flow", url: explorer })]));
    }
  }

  // LP lock — for an established/CEX-listed token, LP-lock % is not a rug signal (liquidity is deep,
  // burned, or widely distributed), so downgrade it to an informational note rather than a sev-3 flag.
  if (g.lp_holders && Array.isArray(g.lp_holders)) {
    const lockedPct = g.lp_holders.reduce((s: number, h: any) => s + (h.is_locked ? (parseFloat(h.percent) || 0) : 0), 0);
    if (lockedPct < 0.5 && g.lp_holders.length > 0) {
      signals.push(established
        ? sig("lp_unlocked", 1, "security", false, 0.5, `Only ${(lockedPct * 100).toFixed(0)}% of LP is locked — not a rug indicator for this established/CEX-listed token (deep, distributed liquidity).`,
            [ev("goplus", `lp_locked=${(lockedPct * 100).toFixed(0)}%`, { url: explorer })])
        : sig("lp_unlocked", 3, "security", false, 0.7, `Only ${(lockedPct * 100).toFixed(0)}% of LP is locked — rug-pull risk.`,
            [ev("goplus", `lp_locked=${(lockedPct * 100).toFixed(0)}%`, { url: explorer })]));
    }
  }

  // no data at all
  if (!gp.ok && !sim?.simulated) {
    return {
      key: "security", verdict: "CAUTION", score: 50, confidence: 0.2, freshness,
      signals: [sig("no_security_data", 2, "security", false, 0.3, `Could not retrieve security data (${gp.error ?? "unknown"}).`, [ev("system", gp.error ?? "no data")])],
      summary: "Insufficient security data — treat with caution.",
    };
  }

  // ---- score + verdict ----
  const hardFlag = signals.some((s) => s.is_hard_flag);
  let score = 100;
  for (const s of signals) {
    if (s.code === "established_token") continue; // positive note, no penalty
    score -= s.severity * s.severity * 1.6; // quadratic penalty
  }
  score = Math.max(0, Math.round(score));
  let verdict: VerdictLabel = score >= 75 ? "GO" : score >= 45 ? "CAUTION" : "AVOID";
  if (hardFlag) { verdict = "AVOID"; score = Math.min(score, 15); }

  // confidence: high when we have a successful sim; lower on static-only or thin data
  let confidence = sim?.simulated ? 0.9 : gp.ok ? 0.65 : 0.3;
  if (meta && !meta.isContract) confidence = Math.min(confidence, 0.4);

  const summary =
    signals.length === 0
      ? "No security red flags detected across simulation and static analysis."
      : (hardFlag ? "Critical security risk: " : "") + signals.slice(0, 3).map((s) => s.finding).join(" ");

  return { key: "security", verdict, score, confidence, signals, freshness, summary };
}

function sig(code: string, severity: 1 | 2 | 3 | 4 | 5, dimension: any, is_hard_flag: boolean, confidence: number, finding: string, evidence: Evidence[]): Signal {
  return { code, severity, dimension, is_hard_flag, confidence, finding, evidence };
}

function short(a: string): string {
  return a.length > 12 ? a.slice(0, 6) + "…" + a.slice(-4) : a;
}
