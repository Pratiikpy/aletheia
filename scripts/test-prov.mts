import { tokenVerdict } from "../src/engine/verdict.js";
const v = await tokenVerdict("ethereum","0x6982508145454ce325ddbe47a25d4ec3d2311933","full");
console.log("provenance:", v.provenance);
