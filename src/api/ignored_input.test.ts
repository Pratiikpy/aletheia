import { describe, expect, it } from "vitest";

import { ignoredInputNote } from "./accepted.js";

/**
 * A field this service does not read must be named, not dropped in silence.
 *
 * Measured on sibling ASPs: a misspelled key turned a request for two venues into five computed from
 * defaults, and a 120-character cap into 8,079 characters. Nothing said the field had been
 * discarded, so the caller was answered a different question from the one they paid for.
 *
 * The accepted set is the union of what each handler reads and what its published Input: contract
 * promises, deliberately generous — a checker that fires on correct calls trains the caller to
 * ignore it, which is worse than not having one.
 */
describe("ignoredInputNote", () => {
  it("names a typo and suggests the field that was meant", () => {
    const note = ignoredInputNote("/verdict", { chain: "ethereum", address: "0x0", teir: "flag" });
    expect(note).toContain("teir");
    expect(note).toContain("did you mean 'tier'");
    expect(note).toContain("may not be the one you intended");
  });

  it("lists what the endpoint does read", () => {
    const note = ignoredInputNote("/verdict", { chain: "e", address: "0x0", nonsense: 1 });
    expect(note).toContain("Accepted fields: address, chain, tier");
  });

  it("says nothing about a correct request", () => {
    expect(ignoredInputNote("/verdict", { chain: "ethereum", address: "0x0", tier: "flag" })).toBeNull();
  });

  it("accepts every spelling a route genuinely supports", () => {
    // /settle takes side_a or sideA; /ask takes question, q, query or subject. Neither is a mistake.
    expect(ignoredInputNote("/settle", { question: "x", side_a: "a", sideB: "b" })).toBeNull();
    expect(ignoredInputNote("/ask", { q: "x" })).toBeNull();
  });

  it("accepts the fields /actionguard resolves downstream", () => {
    // The contract documents these in prose; the handler forwards them rather than reading each.
    expect(ignoredInputNote("/actionguard", { type: "content", content: "x" })).toBeNull();
    expect(ignoredInputNote("/actionguard", { type: "transaction", to: "0x0", data: "0x", value: "0" })).toBeNull();
  });

  it("names several unknown fields at once", () => {
    const note = ignoredInputNote("/verdict", { chain: "e", aaa: 1, bbb: 2 });
    expect(note).toContain("aaa");
    expect(note).toContain("bbb");
    expect(note).toContain("them:");
  });

  it("leaves routes it does not guard alone", () => {
    expect(ignoredInputNote("/receipt/verify", { anything: 1 })).toBeNull();
    expect(ignoredInputNote("/verdict", null)).toBeNull();
    expect(ignoredInputNote("/verdict", [1, 2])).toBeNull();
  });
});

describe("suggestion quality", () => {
  it("catches a transposition, which a prefix rule cannot", () => {
    // 'teir' and 'tier' agree on one character before diverging. This is the case that showed a
    // shared-prefix heuristic was the wrong tool.
    expect(ignoredInputNote("/verdict", { teir: "flag" })).toContain("did you mean 'tier'");
  });

  it("catches an insertion, a deletion and a substitution", () => {
    expect(ignoredInputNote("/verdict", { addres: "0x0" })).toContain("did you mean 'address'");
    expect(ignoredInputNote("/verdict", { chian: "e" })).toContain("did you mean 'chain'");
    expect(ignoredInputNote("/verify", { anwser: "x" })).toContain("did you mean 'answer'");
  });

  it("offers nothing for a field that resembles nothing", () => {
    const note = ignoredInputNote("/verdict", { completely_unrelated_key: 1 });
    expect(note).toContain("completely_unrelated_key");
    expect(note).not.toContain("did you mean");
  });
});
