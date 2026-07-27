import { describe, expect, it } from "vitest";

import { aggregateVerification } from "./verifier.js";

/**
 * A verifier that never says "I don't know" is a rubber stamp.
 *
 * Measured against the live service: the false claim "ETH is the native gas token of X Layer, and
 * OKB is not used for gas" came back VERIFIED with 0.91 agreement, while a false claim about
 * Bitcoin's supply cap was correctly caught. The difference is knowledge, not logic — the models know
 * Bitcoin and do not know X Layer, and the aggregator read the absence of an objection as assent.
 *
 * These pin the arithmetic that decides a verdict. The grounding downgrade itself is asserted in the
 * live checks; what must not drift silently is the rule that agreement alone can mint a VERIFIED.
 */
describe("aggregateVerification", () => {
  it("will not call one model's opinion a consensus", () => {
    const r = aggregateVerification([95]);
    expect(r.verdict).toBe("INSUFFICIENT");
  });

  it("treats wide disagreement as disputed however high the mean", () => {
    const r = aggregateVerification([100, 20, 95]);
    expect(r.verdict).toBe("DISPUTED");
  });

  it("marks a confidently low score as likely wrong, not merely unverified", () => {
    const r = aggregateVerification([10, 15, 5]);
    expect(r.verdict).toBe("LIKELY_WRONG");
    expect(r.agreement).toBeGreaterThan(0.5);
  });

  it("reserves VERIFIED for agreement AND a high mean", () => {
    expect(aggregateVerification([88, 92, 90]).verdict).toBe("VERIFIED");
    // Agreeing on a middling score is not a pass — it is three models hedging together.
    expect(aggregateVerification([55, 58, 60]).verdict).toBe("DISPUTED");
  });

  it("never reports more confidence than agreement allows", () => {
    for (const scores of [[88, 92, 90], [55, 58, 60], [10, 15, 5], [100, 20, 95]]) {
      const r = aggregateVerification(scores);
      expect(r.confidence).toBeLessThanOrEqual(r.agreement);
      expect(r.confidence).toBeLessThanOrEqual(0.95);
    }
  });
});
