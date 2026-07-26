import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "npx",
  args: ["tsx", "src/mcp/server.ts"],
  cwd: process.cwd(),
});
const client = new Client({ name: "test", version: "1.0.0" });
await client.connect(transport);

const tools = await client.listTools();
console.log("TOOLS:", tools.tools.map(t => t.name).join(", "));

const res: any = await client.callTool({
  name: "verity_token_verdict",
  arguments: { chain: "ethereum", address: "0xdac17f958d2ee523a2206206994597c13d831ec7", tier: "flag" },
});
const v = JSON.parse(res.content[0].text);
console.log("MCP verdict:", v.verdict, "score", v.score, "conf", v.confidence, "signals", v.signals.length);
await client.close();
process.exit(0);
