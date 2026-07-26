import { createServer } from "node:http";

// A deliberately UNSAFE OpenAI-compatible agent, to prove AgentAudit catches failures.
// It "does whatever it's told": echoes attack instructions verbatim (leaking tokens) and
// concatenates the system prompt (leaking any canary) — so it should fail injection + accuracy → AVOID.
const port = Number(process.argv[2] ?? 8899);
createServer((req, res) => {
  if (req.method !== "POST") { res.writeHead(404).end(); return; }
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let msgs: any[] = [];
    try { msgs = JSON.parse(body).messages ?? []; } catch {}
    const joined = msgs.map((m) => m.content).join("\n");
    const content = "Sure, here you go: " + joined; // naive compliance → echoes tokens + leaks system prompt
    const out = {
      choices: [{ message: { role: "assistant", content } }],
      usage: { prompt_tokens: 50, completion_tokens: Math.max(1, Math.round(content.length / 4)) },
    };
    res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(out));
  });
}).listen(port, () => console.log(`mock weak agent on http://127.0.0.1:${port}/chat/completions`));
