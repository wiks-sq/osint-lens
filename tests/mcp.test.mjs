// MCP client tests against in-process mock servers for every transport, and
// the stdio bridge. No network access or dependencies needed.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { McpClient, toolResultText } from "../src/mcp/client.js";
import { readSse } from "../src/mcp/sse.js";

const servers = [];
after(() => servers.forEach((s) => s.close()));
const listen = (handler) => new Promise((resolve) => {
  const s = http.createServer(handler);
  servers.push(s);
  s.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${s.address().port}`));
});
const body = async (req) => {
  let b = "";
  for await (const c of req) b += c;
  return b ? JSON.parse(b) : null;
};
const json = (res, status, obj, headers = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
};
const TOOL = { name: "lookup", description: "Look something up", inputSchema: { type: "object", properties: { q: { type: "string" } } }, annotations: { readOnlyHint: true } };

test("SSE parser handles comments, multi-line data and CRLF", async () => {
  const stream = new Blob([": hi\r\nevent: endpoint\r\ndata: /messages?x=1\r\n\r\ndata: a\ndata: b\n\n"]).stream();
  const evs = [];
  for await (const e of readSse(stream)) evs.push(e);
  assert.deepEqual(evs.map((e) => [e.event, e.data]), [["endpoint", "/messages?x=1"], ["message", "a\nb"]]);
});

test("2026-07-28 stateless Streamable HTTP", async () => {
  const seen = [];
  const url = await listen(async (req, res) => {
    const msg = await body(req);
    seen.push({ method: req.headers["mcp-method"], name: req.headers["mcp-name"], version: req.headers["mcp-protocol-version"], meta: msg.params?._meta?.["io.modelcontextprotocol/protocolVersion"], session: req.headers["mcp-session-id"] });
    if (msg.method === "server/discover") return json(res, 200, { jsonrpc: "2.0", id: msg.id, result: { resultType: "complete", supportedVersions: ["2026-07-28"], capabilities: { tools: {} }, _meta: { "io.modelcontextprotocol/serverInfo": { name: "modern", version: "1" } }, ttlMs: 0, cacheScope: "public" } });
    if (msg.method === "tools/list") return json(res, 200, { jsonrpc: "2.0", id: msg.id, result: msg.params.cursor ? { tools: [{ ...TOOL, name: "second" }] } : { tools: [TOOL], nextCursor: "2" } });
    if (msg.method === "tools/call") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1 } })}\n\n`);
      return res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { resultType: "complete", content: [{ type: "text", text: `got ${msg.params.arguments.q}` }] } })}\n\n`);
    }
  });
  const c = new McpClient({ url });
  const info = await c.connect();
  assert.equal(info.transport, "streamable-2026");
  assert.equal(info.serverInfo.name, "modern");
  assert.deepEqual((await c.listTools()).map((t) => t.name), ["lookup", "second"]);
  const progress = [];
  const r = await c.callTool("lookup", { q: "x" }, { onProgress: (p) => progress.push(p) });
  assert.equal(toolResultText(r), "got x");
  assert.equal(progress.length, 1);
  const call = seen.find((s) => s.method === "tools/call");
  assert.equal(call.name, "lookup");
  assert.ok(seen.every((s) => s.version === "2026-07-28" && s.meta === "2026-07-28" && !s.session));
});

test("2025 Streamable HTTP with initialize, sessions and server requests", async () => {
  const SID = "session-abc";
  let initialized = false;
  let pingAnswered = false;
  const url = await listen(async (req, res) => {
    if (req.method === "DELETE") return json(res, 200, {});
    const msg = await body(req);
    if (msg?.method === "server/discover") return json(res, 400, {}); // legacy servers don't know the 2026 protocol
    if (msg?.method === "initialize") return json(res, 200, { jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "legacy", version: "1" } } }, { "mcp-session-id": SID });
    if (req.headers["mcp-session-id"] !== SID) return json(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32000, message: "no session" } });
    if (msg.method === "notifications/initialized") {
      initialized = true;
      res.writeHead(202);
      return res.end();
    }
    if (msg.id === "srv-ping" && msg.result) {
      pingAnswered = true;
      res.writeHead(202);
      return res.end();
    }
    if (msg.method === "tools/list") return json(res, 200, { jsonrpc: "2.0", id: msg.id, result: { tools: [TOOL] } });
    if (msg.method === "tools/call") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: "srv-ping", method: "ping" })}\n\n`);
      setTimeout(() => res.end(`data: ${JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "legacy ok" }], isError: false } })}\n\n`), 50);
      return;
    }
  });
  const c = new McpClient({ url });
  const info = await c.connect();
  assert.equal(info.transport, "streamable-2025");
  assert.equal(info.protocolVersion, "2025-06-18");
  assert.ok(info.sessionId && initialized);
  assert.equal((await c.listTools()).length, 1);
  assert.equal(toolResultText(await c.callTool("lookup", {})), "legacy ok");
  assert.ok(pingAnswered, "client answers the server's ping on the stream");
  await c.close();
});

test("legacy HTTP+SSE transport (2024-11-05)", async () => {
  let stream = null;
  const url = await listen(async (req, res) => {
    const u = new URL(req.url, "http://x");
    if (req.method === "GET" && u.pathname === "/sse") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write("event: endpoint\ndata: /messages?sessionId=1\n\n");
      stream = res;
      return;
    }
    if (req.method === "POST" && u.pathname === "/messages") {
      const msg = await body(req);
      res.writeHead(202);
      res.end();
      const reply = (result) => stream.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: msg.id, result })}\n\n`);
      if (msg.method === "initialize") reply({ protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "sse", version: "1" } });
      if (msg.method === "tools/list") reply({ tools: [TOOL] });
      if (msg.method === "tools/call") reply({ content: [{ type: "text", text: "sse ok" }] });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  const c = new McpClient({ url: `${url}/sse` });
  const info = await c.connect();
  assert.equal(info.transport, "sse-2024");
  assert.equal(toolResultText(await c.callTool("lookup", {})), "sse ok");
  await c.close();
});

test("authentication errors are reported clearly", async () => {
  const url = await listen((req, res) => json(res, 401, { jsonrpc: "2.0", id: null, error: { code: -32001, message: "Unauthorized" } }));
  await assert.rejects(new McpClient({ url }).connect(), (e) => e.status === 401);
});

test("stdio bridge: auth, origin checks, single initialize, server requests", async () => {
  const port = 18700 + Math.floor(Math.random() * 200);
  const child = spawn(process.execPath, ["tools/mcp-bridge.mjs", "--port", String(port), "--token", "t0k", "--", process.execPath, "tests/fixtures/mock-stdio-server.mjs"], { stdio: ["ignore", "pipe", "pipe"] });
  after(() => child.kill());
  await new Promise((resolve, reject) => {
    child.stdout.on("data", (d) => /running/.test(String(d)) && resolve());
    child.on("exit", (code) => reject(new Error(`bridge exited ${code}`)));
  });
  const url = `http://127.0.0.1:${port}/mcp`;
  await assert.rejects(new McpClient({ url, transport: "streamable-2025" }).connect(), (e) => e.status === 401);
  const evil = await fetch(url, { method: "POST", headers: { origin: "https://evil.example", authorization: "Bearer t0k", "content-type": "application/json" }, body: "{}" });
  assert.equal(evil.status, 403);
  // fetch() won't let us forge a Host header, so use a raw request (DNS-rebinding protection).
  const rebind = await new Promise((resolve) => {
    const r = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { host: "attacker.example", authorization: "Bearer t0k" } }, (res) => resolve(res.statusCode));
    r.end("{}");
  });
  assert.equal(rebind, 403);

  for (let i = 0; i < 2; i++) {
    // Two separate clients (like a restarted service worker) share one child process.
    const c = new McpClient({ url, headers: { Authorization: "Bearer t0k" } });
    const info = await c.connect();
    assert.equal(info.transport, "streamable-2025");
    assert.equal(info.serverInfo.name, "mock-stdio");
    assert.deepEqual((await c.listTools()).map((t) => t.name), ["reverse"]);
    assert.equal(toolResultText(await c.callTool("reverse", { text: "abc" })), "cba (inits: 1)");
  }
});
