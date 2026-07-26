import { chat, chatJson, jury } from "../src/ai/router.js";
// cheap tier
const c = await chat([{ role: "user", content: "In 6 words, what is a crypto honeypot token?" }], { tier: "cheap", maxTokens: 200 });
console.log("cheap:", c.model, "->", c.content.trim(), "| cost(wei):", c.costWei);
// json structured
const j = await chatJson<{ verdict: string; reason: string }>([
  { role: "system", content: "You are a risk classifier. Return JSON {verdict, reason}." },
  { role: "user", content: "A token where owner can rewrite balances and mint freely, only 3 holders, LP unlocked." },
], { tier: "cheap", maxTokens: 300 });
console.log("json:", j.model, "->", JSON.stringify(j.data));
// jury
const j2 = await jury([{ role: "user", content: "One word: is buying a token you can't sell wise? yes/no" }], ["cheap","strong"], { maxTokens: 50 });
console.log("jury:", j2.map(x=>`${x.model}:${x.content.trim().slice(0,20)}`).join(" | "));
