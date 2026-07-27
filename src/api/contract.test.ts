/**
 * Every field a service advertises must be a field it actually reads.
 *
 * `/research` published `Input: {subject | question}` in its x402 challenge and accepted every name
 * except `question`. A caller who followed the documentation paid $0.10 and received a 400. The
 * description is not decoration — it is the only contract a buying agent has, and it is delivered
 * before the money moves, so a promise made there is a promise the handler has to keep.
 *
 * The check is deliberately static. Calling these routes for real would mean network access, model
 * spend and a live wallet in the unit suite; parsing what the challenge claims and confirming the
 * handler reads it catches the defect that actually occurred, at no cost.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER_SRC = readFileSync(join(HERE, "server.ts"), "utf8");
const OKXPAY_SRC = readFileSync(join(HERE, "okxpay.ts"), "utf8");

/** Pull `Input: {a, b?, c}` out of each route description in okxpay.ts's ROUTES table. */
function advertisedInputs(): Array<{ route: string; fields: string[] }> {
  const out: Array<{ route: string; fields: string[] }> = [];
  const routeBlock = /"(\/[^"]+)":\s*\{[\s\S]*?description:\s*"((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = routeBlock.exec(OKXPAY_SRC)) !== null) {
    const [, route, description] = m;
    const input = /Input:\s*\{([^}]*)\}/.exec(description);
    if (!input) continue;
    const fields = input[1]
      .split(",")
      // Drop the prose that documents an enum's values, e.g. "tier?: 'flag' | 'full'".
      .map((part) => part.split(":")[0].trim().replace(/\?$/, ""))
      .filter((name) => /^[a-z_][a-z0-9_]*$/i.test(name));
    if (fields.length) out.push({ route, fields });
  }
  return out;
}

const ADVERTISED = advertisedInputs();

describe("the published input contract", () => {
  it("was parsed from the live route table, not hard-coded here", () => {
    // If the regex ever stops matching, every assertion below would vacuously pass.
    expect(ADVERTISED.length).toBeGreaterThan(5);
  });

  it.each(ADVERTISED)("$route reads every field it advertises", ({ route, fields }) => {
    const unread = fields.filter((f) => !SERVER_SRC.includes(`body.${f}`));
    expect(
      unread,
      `${route} advertises ${unread.join(", ")} in its challenge but never reads ` +
        `body.${unread[0] ?? ""} — a caller who follows the documentation pays and gets an error`,
    ).toEqual([]);
  });

  it("/research accepts the question field its own description names", () => {
    // Scoped to this handler on purpose: several routes declare `const subject = body.subject …`,
    // and matching the first one tested /check while claiming to test /research.
    const handler = /app\.post\("\/research"[\s\S]*?\n\}\);/.exec(SERVER_SRC)?.[0] ?? "";
    expect(handler, "the /research handler was not found").not.toEqual("");
    expect(handler).toContain("body.question");
  });
});
