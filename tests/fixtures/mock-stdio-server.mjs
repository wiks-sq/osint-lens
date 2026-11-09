// A minimal stdio MCP server used by the bridge tests (no dependencies).
import { createInterface } from "node:readline";
const send = (m) => process.stdout.write(`${JSON.stringify(m)}\n`);
let initialized = 0;
createInterface({ input: process.stdin }).on("line", (line) => {
  const msg = JSON.parse(line);
  if (msg.method === "initialize") {
    initialized++;
    return send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: msg.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "mock-stdio", version: "1.0.0" } } });
  }
  if (msg.method === "notifications/initialized") return;
  if (msg.method === "tools/list") return send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "reverse", description: "Reverse a string", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }] } });
  if (msg.method === "tools/call") {
    // Ask the client something first: the bridge must answer this itself.
    send({ jsonrpc: "2.0", id: "srv-1", method: "roots/list" });
    return send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `${[...msg.params.arguments.text].reverse().join("")} (inits: ${initialized})` }] } });
  }
  if (msg.id !== undefined && msg.method) send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
});
