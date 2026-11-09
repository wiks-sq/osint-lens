#!/usr/bin/env node
// OSINT Lens MCP bridge: exposes local stdio MCP servers over Streamable HTTP
// so the browser extension can use them. Zero dependencies (Node 18+).
//
// A browser extension can't start processes, and most MCP servers are stdio
// programs ("npx some-mcp-server"). This bridge runs them and forwards
// JSON-RPC between HTTP and each server's stdin/stdout.
//
// Usage
//   One server:
//     node tools/mcp-bridge.mjs -- npx -y @modelcontextprotocol/server-everything
//     -> http://127.0.0.1:8765/mcp
//
//   Several servers from a config file (Claude Desktop "mcpServers" format works as-is):
//     node tools/mcp-bridge.mjs --config mcp-servers.json
//     -> http://127.0.0.1:8765/<name>/mcp for each server
//
// Options
//   --port <n>          listen port (default 8765)
//   --host <addr>       listen address (default 127.0.0.1; keep it local)
//   --token <secret>    required bearer token (default: random, printed at start)
//   --no-auth           don't require a token (only for throwaway local testing)
//   --allow-origin <o>  allowed Origin, repeatable (default: any chrome-extension:// origin)
//   --timeout <sec>     per-request timeout (default 120)
//
// Security: the bridge only listens on localhost, requires a bearer token, and
// rejects requests from web pages (Origin must be an extension) and requests
// whose Host header isn't localhost (DNS-rebinding protection).

import http from "node:http";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
const opts = { port: 8765, host: "127.0.0.1", token: null, auth: true, origins: [], timeout: 120, config: null, command: null };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--") {
    opts.command = argv.slice(i + 1);
    break;
  }
  if (a === "--port") opts.port = Number(argv[++i]);
  else if (a === "--host") opts.host = argv[++i];
  else if (a === "--token") opts.token = argv[++i];
  else if (a === "--no-auth") opts.auth = false;
  else if (a === "--allow-origin") opts.origins.push(argv[++i]);
  else if (a === "--timeout") opts.timeout = Number(argv[++i]);
  else if (a === "--config") opts.config = argv[++i];
  else if (a === "-h" || a === "--help") {
    console.log(readFileSync(new URL(import.meta.url)).toString().split("\n").filter((l) => l.startsWith("//")).map((l) => l.slice(3)).join("\n"));
    process.exit(0);
  } else {
    console.error(`Unknown option ${a}. Use --help.`);
    process.exit(2);
  }
}
if (!opts.config && !opts.command?.length) {
  console.error("Give a server command after --, or --config <file>. See --help.");
  process.exit(2);
}
if (opts.auth && !opts.token) opts.token = randomBytes(18).toString("base64url");

/** @type {Map<string, {command:string, args:string[], env:object, cwd?:string}>} */
const defs = new Map();
if (opts.config) {
  const cfg = JSON.parse(readFileSync(opts.config, "utf8"));
  const servers = cfg.mcpServers || cfg.servers || cfg;
  for (const [name, s] of Object.entries(servers)) {
    if (!s || typeof s !== "object" || !s.command) continue;
    if (!/^[A-Za-z0-9_.\-]+$/.test(name)) {
      console.error(`Skipping server "${name}": names may only contain letters, digits, . _ -`);
      continue;
    }
    defs.set(name, { command: s.command, args: s.args || [], env: s.env || {}, cwd: s.cwd });
  }
} else {
  defs.set("", { command: opts.command[0], args: opts.command.slice(1), env: {} });
}

// ---------------------------------------------------------------------------
// Child process wrapper
// ---------------------------------------------------------------------------

class StdioServer {
  constructor(name, def) {
    this.name = name;
    this.def = def;
    this.proc = null;
    this.pending = new Map();
    this.buf = "";
    this.initResult = null;
    this.initializing = null;
    this.nextId = 1;
  }

  start() {
    if (this.proc) return;
    const label = this.name || "server";
    this.proc = spawn(this.def.command, this.def.args, {
      env: { ...process.env, ...this.def.env },
      cwd: this.def.cwd,
      stdio: ["pipe", "pipe", "pipe"],
      shell: process.platform === "win32"
    });
    this.proc.stdout.setEncoding("utf8");
    this.proc.stdout.on("data", (d) => this.#onData(d));
    this.proc.stderr.on("data", (d) => process.stderr.write(`[${label}] ${d}`));
    this.proc.on("exit", (code, sig) => {
      console.error(`[${label}] exited (${sig || code}); it will restart on the next request`);
      for (const p of this.pending.values()) p.reject(new Error(`MCP server exited (${sig || code})`));
      this.pending.clear();
      this.proc = null;
      this.initResult = null;
      this.initializing = null;
      this.buf = "";
    });
    this.proc.on("error", (e) => console.error(`[${label}] failed to start: ${e.message}`));
  }

  #onData(chunk) {
    this.buf += chunk;
    let nl;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        process.stderr.write(`[${this.name || "server"}] non-JSON output: ${line.slice(0, 200)}\n`);
        continue;
      }
      this.#onMessage(msg);
    }
  }

  #onMessage(msg) {
    if (msg.id !== undefined && msg.id !== null && ("result" in msg || "error" in msg)) {
      const p = this.pending.get(String(msg.id));
      if (p) {
        this.pending.delete(String(msg.id));
        p.resolve(msg);
      }
      return;
    }
    if (msg.method && msg.id !== undefined) {
      // Server -> client request. The browser client can't answer these over a
      // plain request/response bridge, so we answer them here.
      const reply = msg.method === "ping"
        ? { jsonrpc: "2.0", id: msg.id, result: {} }
        : msg.method === "roots/list"
          ? { jsonrpc: "2.0", id: msg.id, result: { roots: [] } }
          : { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `${msg.method} is not supported through the bridge` } };
      this.#write(reply);
    }
    // Notifications (logging, progress, list_changed) are dropped.
  }

  #write(obj) {
    this.start();
    this.proc.stdin.write(`${JSON.stringify(obj)}\n`);
  }

  /** Send a request with our own id (avoids clashes between HTTP clients) and map the response back. */
  request(msg, timeoutMs) {
    this.start();
    const ourId = `b${this.nextId++}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(ourId);
        reject(new Error(`MCP server didn't answer ${msg.method} within ${timeoutMs / 1000}s`));
      }, timeoutMs);
      this.pending.set(ourId, {
        resolve: (r) => {
          clearTimeout(timer);
          resolve({ ...r, id: msg.id });
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        }
      });
      this.#write({ ...msg, id: ourId });
    });
  }

  notify(msg) {
    this.#write(msg);
  }

  /**
   * The child is one long-lived session, but the extension may reconnect many
   * times (its service worker restarts). Initialize the child once and replay
   * the cached result to later clients.
   */
  async initialize(msg, timeoutMs) {
    if (this.initResult) return { jsonrpc: "2.0", id: msg.id, result: this.initResult };
    if (!this.initializing) {
      this.initializing = this.request({ ...msg, id: "init" }, timeoutMs).then((r) => {
        if (r.result) {
          this.initResult = r.result;
          this.notify({ jsonrpc: "2.0", method: "notifications/initialized" });
        } else this.initializing = null;
        return r;
      }, (e) => {
        this.initializing = null;
        throw e;
      });
    }
    const r = await this.initializing;
    return { ...r, id: msg.id };
  }
}

const servers = new Map([...defs].map(([n, d]) => [n, new StdioServer(n, d)]));

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

function originAllowed(origin) {
  if (!origin) return true; // non-browser clients (curl, other tools) send no Origin
  if (opts.origins.length) return opts.origins.includes(origin);
  return /^chrome-extension:\/\/[a-p]{32}$/.test(origin) || /^moz-extension:\/\//.test(origin);
}

function send(res, status, body, headers = {}) {
  const data = body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(data);
}

const rpcError = (id, code, message) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  const cors = origin && originAllowed(origin) ? { "access-control-allow-origin": origin, vary: "Origin" } : {};
  const hostHeader = String(req.headers.host || "").replace(/:\d+$/, "");
  if (!LOCAL_HOSTS.has(hostHeader) && opts.host === "127.0.0.1") return send(res, 403, rpcError(null, -32000, "Invalid Host header"));
  if (!originAllowed(origin)) return send(res, 403, rpcError(null, -32000, `Origin ${origin} not allowed`));

  if (req.method === "OPTIONS") {
    res.writeHead(204, { ...cors, "access-control-allow-methods": "GET, POST, DELETE, OPTIONS", "access-control-allow-headers": "authorization, content-type, accept, mcp-protocol-version, mcp-session-id, mcp-method, mcp-name", "access-control-max-age": "86400" });
    return res.end();
  }

  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && url.pathname === "/") {
    return send(res, 200, { bridge: "osint-lens-mcp-bridge", servers: [...servers.keys()].map((n) => ({ name: n || "(default)", url: `/${n ? `${n}/` : ""}mcp`, running: !!servers.get(n).proc })) }, cors);
  }

  const m = /^\/(?:([A-Za-z0-9_.\-]+)\/)?mcp\/?$/.exec(url.pathname);
  const target = m ? servers.get(m[1] || "") : null;
  if (!target) return send(res, 404, rpcError(null, -32601, "No MCP server at this path. GET / lists them."), cors);

  if (opts.auth && req.headers.authorization !== `Bearer ${opts.token}`) {
    return send(res, 401, rpcError(null, -32001, "Missing or wrong bearer token"), { ...cors, "www-authenticate": 'Bearer realm="osint-lens-mcp-bridge"' });
  }
  if (req.method === "GET") return send(res, 405, rpcError(null, -32000, "This bridge doesn't offer a server-initiated stream"), { ...cors, allow: "POST, DELETE" });
  if (req.method === "DELETE") return send(res, 200, {}, cors);
  if (req.method !== "POST") return send(res, 405, rpcError(null, -32000, "Method not allowed"), cors);

  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 10e6) return send(res, 413, rpcError(null, -32000, "Request too large"), cors);
  }
  let msg;
  try {
    msg = JSON.parse(body);
  } catch {
    return send(res, 400, rpcError(null, -32700, "Parse error"), cors);
  }
  if (Array.isArray(msg)) return send(res, 400, rpcError(null, -32600, "Batches are not supported"), cors);

  try {
    // Requests from the 2026 stateless protocol: tell the client to use the handshake instead.
    if (msg.method === "server/discover") return send(res, 404, rpcError(msg.id, -32601, "Method not found: server/discover"), cors);
    if (msg.method === "initialize") return send(res, 200, await target.initialize(msg, opts.timeout * 1000), cors);
    if (msg.id === undefined) {
      if (msg.method !== "notifications/initialized") target.notify(msg);
      res.writeHead(202, cors);
      return res.end();
    }
    if (msg.method === "ping") return send(res, 200, { jsonrpc: "2.0", id: msg.id, result: {} }, cors);
    if (!target.initResult) await target.initialize({ jsonrpc: "2.0", id: "auto", method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "osint-lens-mcp-bridge", version: "1.0.0" } } }, opts.timeout * 1000);
    send(res, 200, await target.request(msg, opts.timeout * 1000), cors);
  } catch (e) {
    send(res, 502, rpcError(msg.id, -32603, e.message), cors);
  }
});

server.listen(opts.port, opts.host, () => {
  const base = `http://${opts.host === "0.0.0.0" ? "127.0.0.1" : opts.host}:${opts.port}`;
  console.log("OSINT Lens MCP bridge is running.\n");
  for (const n of servers.keys()) console.log(`  ${n || "server"}: ${base}/${n ? `${n}/` : ""}mcp`);
  if (opts.auth) {
    console.log(`\nIn the extension's MCP settings add the header:\n  Authorization: Bearer ${opts.token}\n`);
    if (!argv.includes("--token")) console.log("(Pass --token <secret> to keep the same token across restarts.)\n");
  } else console.log("\nWARNING: authentication is disabled (--no-auth).\n");
  if (opts.host !== "127.0.0.1" && opts.host !== "localhost") console.log("WARNING: listening on a non-local address. Anyone who can reach it and has the token can use your MCP servers.\n");
});

const shutdown = () => {
  for (const s of servers.values()) s.proc?.kill();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
