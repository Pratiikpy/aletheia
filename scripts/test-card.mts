import { tokenVerdict } from "../src/engine/verdict.js";
import { verdictCardMarkdown, verdictCardTweet } from "../src/engine/card.js";
const v = await tokenVerdict("ethereum", "0x6982508145454ce325ddbe47a25d4ec3d2311933", "full");
console.log("=== MARKDOWN CARD ===\n");
console.log(verdictCardMarkdown(v));
console.log("\n=== TWEET ("+verdictCardTweet(v).length+" chars) ===\n");
console.log(verdictCardTweet(v));
