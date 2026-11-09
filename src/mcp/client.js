// A Model Context Protocol client for remote (HTTP) MCP servers, written for
// browser fetch() and with no dependencies.
//
// Supported transports, detected automatically or chosen in settings:
//   "streamable-2026"  Streamable HTTP, protocol 2026-07-28: stateless, every
//                      request carries its version and client info in _meta.
//   "streamable-2025"  Streamable HTTP with an initialize handshake and an
//                      optional Mcp-Session-Id (protocol 2025-03-26 .. 2025-11-25).
//   "sse-2024"         The original HTTP+SSE transport (protocol 2024-11-05):
//                      a GET event stream plus POSTs to an "endpoint" URL.
//
// Browsers can't spawn processes, so stdio servers are reached through a
// bridge that exposes them over HTTP (tools/mcp-bridge.mjs in this repo, or
// any stdio-to-HTTP proxy).

import { readSse } from "./sse.js";

export const MODERN_VERSION = "2026-07-28";
export const LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
export const CLIENT_INFO = { name: "osint-lens", title: "OSINT Lens", version: "2.0.0" };

export class McpError extends Error {
  constructor(message, { code = null, status = 0, data = null } = {}) {
    super(message);
    this.name = "McpError";
    this.code = code;
    this.status = status;
    this.data = data;
  }
}

const isModernErrorCode = (c) => c === -32020 || c === -32021 || c === -32022;

export class McpClient {
  /**
   * @param {object} cfg
   * @param {string} cfg.url
   * @param {"auto"|"streamable-2026"|"streamable-2025"|"sse-2024"} [cfg.transport]
   * @param {Object<string,string>} [cfg.headers]  extra headers, e.g. Authorization
   * @param {number} [cfg.timeoutMs]
   */
  constructor(cfg) {
    this.url = cfg.url;
    this.transport = cfg.transport && cfg.transport !== "auto" ? cfg.transport : null;
    this.extraHeaders = cfg.headers || {};
    this.timeoutMs = cfg.timeoutMs || 60000;
    this.protocolVersion = null;
    this.sessionId = null;
    this.serverInfo = null;
    this.capabilities = null;
    this.instructions = null;
    this.nextId = 1;
    this.connected = false;
    // sse-2024 state
    this.sseEndpoint = null;
    this.ssePending = new Map();
    this.sseAbort = null;
  }

  // -------------------------------------------------------------------------
  // Connection
  // -------------------------------------------------------------------------

  async connect() {
    if (this.connected) return this.info();
    const order = this.transport ? [this.transport] : ["streamable-2026", "streamable-2025", "sse-2024"];
    let lastErr;
    for (const t of order) {
      try {
        if (t === "streamable-2026") await this.#connectModern();
        else if (t === "streamable-2025") await this.#connectLegacy();
        else await this.#connectSse();
        this.transport = t;
        this.connected = true;
        return this.info();
      } catch (e) {
        lastErr = e;
        // Authentication and network failures won't be fixed by another transport.
        if (e.status === 401 || e.status === 403 || (e.status === 0 && /reach|timed out/i.test(e.message))) break;
      }
    }
    throw lastErr;
  }

  info() {
    return { transport: this.transport, protocolVersion: this.protocolVersion, serverInfo: this.serverInfo, capabilities: this.capabilities, instructions: this.instructions, sessionId: !!this.sessionId, warning: this.versionWarning || null };
  }

  async #connectModern() {
    this.protocolVersion = MODERN_VERSION;
    let res;
    try {
      res = await this.#rpcModern("server/discover", {});
    } catch (e) {
      // A modern server that doesn't speak our version tells us which ones it does.
      if (e.code === -32022 && Array.isArray(e.data?.supported)) {
        if (e.data.supported.includes(MODERN_VERSION)) throw e;
        if (e.data.supported.some((v) => LEGACY_VERSIONS.includes(v))) throw new McpError("Server prefers a handshake-based protocol version", { status: 400 });
      }
      throw e;
    }
    if (!res || !Array.isArray(res.supportedVersions)) throw new McpError("Not a 2026-07-28 server (no supportedVersions in server/discover)");
    if (!res.supportedVersions.includes(MODERN_VERSION)) throw new McpError(`Server supports ${res.supportedVersions.join(", ")}`);
    this.capabilities = res.capabilities || {};
    this.instructions = res.instructions || null;
    this.serverInfo = res._meta?.["io.modelcontextprotocol/serverInfo"] || null;
  }

  async #connectLegacy() {
    // Ask for the newest handshake version first. If the server answers with a
    // version we don't know, retry with older ones; if none matches, carry on
    // with the server's choice (the message shapes we use are stable).
    let result = null;
    for (const v of LEGACY_VERSIONS.slice(0, 3)) {
      this.protocolVersion = null;
      this.sessionId = null;
      result = await this.#rpcLegacy("initialize", { protocolVersion: v, capabilities: {}, clientInfo: CLIENT_INFO }, { initialize: true });
      if (!result?.protocolVersion) throw new McpError("Invalid initialize result");
      if (LEGACY_VERSIONS.includes(result.protocolVersion)) break;
      if (this.sessionId) await this.#fetch(this.url, { method: "DELETE", headers: this.#legacyHeaders() }, 5000).then((r) => r.body?.cancel()).catch(() => {});
    }
    this.protocolVersion = result.protocolVersion;
    this.versionWarning = LEGACY_VERSIONS.includes(result.protocolVersion) ? null : `Server negotiated unknown protocol version "${result.protocolVersion}"`;
    this.capabilities = result.capabilities || {};
    this.serverInfo = result.serverInfo || null;
    this.instructions = result.instructions || null;
    await this.#notifyLegacy("notifications/initialized");
  }

  async #connectSse() {
    this.sseAbort = new AbortController();
    const res = await this.#fetch(this.url, { method: "GET", headers: { accept: "text/event-stream", ...this.extraHeaders }, signal: this.sseAbort.signal }, 0);
    if (!res.ok || !/text\/event-stream/i.test(res.headers.get("content-type") || "")) {
      this.sseAbort.abort();
      throw new McpError(`SSE endpoint returned HTTP ${res.status}`, { status: res.status });
    }
    const gotEndpoint = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new McpError("No endpoint event from SSE server")), 15000);
      (async () => {
        try {
          for await (const ev of readSse(res.body)) {
            if (ev.event === "endpoint") {
              this.sseEndpoint = new URL(ev.data.trim(), this.url).href;
              clearTimeout(timer);
              resolve();
            } else if (ev.event === "message") {
              this.#dispatchSse(ev.data);
            }
          }
        } catch (e) {
          clearTimeout(timer);
          reject(e);
        } finally {
          this.connected = false;
          for (const p of this.ssePending.values()) p.reject(new McpError("SSE stream closed"));
          this.ssePending.clear();
        }
      })();
    });
    await gotEndpoint;
    const result = await this.#rpcSse("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: CLIENT_INFO });
    this.protocolVersion = result.protocolVersion || "2024-11-05";
    this.capabilities = result.capabilities || {};
    this.serverInfo = result.serverInfo || null;
    this.instructions = result.instructions || null;
    await this.#postSse({ jsonrpc: "2.0", method: "notifications/initialized" });
  }

  async close() {
    try {
      if (this.transport === "streamable-2025" && this.sessionId) {
        await this.#fetch(this.url, { method: "DELETE", headers: this.#legacyHeaders() }, 5000).catch(() => {});
      }
    } finally {
      this.sseAbort?.abort();
      this.connected = false;
      this.sessionId = null;
    }
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  async request(method, params = {}, o = {}) {
    if (!this.connected) await this.connect();
    if (this.transport === "streamable-2026") return this.#rpcModern(method, params, o);
    if (this.transport === "sse-2024") return this.#rpcSse(method, params, o);
    try {
      return await this.#rpcLegacy(method, params, o);
    } catch (e) {
      // Session expired: the spec says start over with a new initialize.
      if (e.status === 404 && this.sessionId) {
        await this.#connectLegacy();
        return this.#rpcLegacy(method, params, o);
      }
      throw e;
    }
  }

  async #paginate(method, key, o) {
    const out = [];
    let cursor;
    for (let page = 0; page < 50; page++) {
      const r = await this.request(method, cursor ? { cursor } : {}, o);
      out.push(...(r?.[key] || []));
      cursor = r?.nextCursor;
      if (!cursor) break;
    }
    return out;
  }

  listTools(o) {
    return this.#paginate("tools/list", "tools", o);
  }

  listResources(o) {
    return this.#paginate("resources/list", "resources", o);
  }

  listPrompts(o) {
    return this.#paginate("prompts/list", "prompts", o);
  }

  readResource(uri, o) {
    return this.request("resources/read", { uri }, o);
  }

  getPrompt(name, args, o) {
    return this.request("prompts/get", { name, arguments: args || {} }, o);
  }

  /**
   * Call a tool. Resolves to the CallToolResult ({content, structuredContent, isError}).
   * Interactive follow-ups (sampling, elicitation) are not supported and come back as an error result.
   */
  async callTool(name, args, o = {}) {
    const r = await this.request("tools/call", { name, arguments: args || {} }, { ...o, mcpName: name });
    if (r?.resultType === "input_required") {
      return { isError: true, content: [{ type: "text", text: "The server asked for interactive input (sampling or elicitation), which this client does not support." }] };
    }
    return r;
  }

  // -------------------------------------------------------------------------
  // Transports
  // -------------------------------------------------------------------------

  /**
   * fetch() with a timeout that covers reading the body too (AbortSignal.timeout
   * keeps running while a streamed response is consumed). timeoutMs 0 = none.
   */
  async #fetch(url, init, timeoutMs = this.timeoutMs) {
    const signals = [init.signal, timeoutMs ? AbortSignal.timeout(timeoutMs) : null].filter(Boolean);
    const signal = signals.length > 1 ? AbortSignal.any(signals) : signals[0];
    try {
      return await fetch(url, { ...init, signal, credentials: "omit", cache: "no-store" });
    } catch (e) {
      if (init.signal?.aborted) throw new McpError("Cancelled");
      if (e.name === "TimeoutError" || signal?.aborted) throw new McpError(`MCP server timed out after ${Math.round(timeoutMs / 1000)}s`, { status: 0 });
      throw new McpError(`Couldn't reach the MCP server at ${url} (${e.message})`, { status: 0 });
    }
  }

  #meta() {
    return {
      "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
      "io.modelcontextprotocol/clientInfo": { name: CLIENT_INFO.name, version: CLIENT_INFO.version },
      "io.modelcontextprotocol/clientCapabilities": {}
    };
  }

  async #rpcModern(method, params, o = {}) {
    const id = this.nextId++;
    const body = { jsonrpc: "2.0", id, method, params: { ...params, _meta: { ...(params._meta || {}), ...this.#meta() } } };
    const headers = {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-protocol-version": MODERN_VERSION,
      "mcp-method": method,
      ...this.extraHeaders
    };
    const name = method === "tools/call" || method === "prompts/get" ? params.name : method === "resources/read" ? params.uri : null;
    if (name) headers["mcp-name"] = /^[\x20-\x7e]*$/.test(name) ? name : `=?base64?${btoa(unescape(encodeURIComponent(name)))}?=`;
    const res = await this.#fetch(this.url, { method: "POST", headers, body: JSON.stringify(body), signal: o.signal });
    return this.#readResponse(res, id, o, { modern: true });
  }

  #legacyHeaders(extra = {}) {
    const h = { accept: "application/json, text/event-stream", "content-type": "application/json", ...this.extraHeaders, ...extra };
    if (this.protocolVersion) h["mcp-protocol-version"] = this.protocolVersion;
    if (this.sessionId) h["mcp-session-id"] = this.sessionId;
    return h;
  }

  async #rpcLegacy(method, params, o = {}) {
    const id = this.nextId++;
    const res = await this.#fetch(this.url, { method: "POST", headers: this.#legacyHeaders(), body: JSON.stringify({ jsonrpc: "2.0", id, method, params }), signal: o.signal });
    if (o.initialize) {
      const sid = res.headers.get("mcp-session-id");
      if (sid) this.sessionId = sid;
    }
    return this.#readResponse(res, id, o, { modern: false });
  }

  async #notifyLegacy(method, params) {
    const res = await this.#fetch(this.url, { method: "POST", headers: this.#legacyHeaders(), body: JSON.stringify({ jsonrpc: "2.0", method, ...(params ? { params } : {}) }) });
    if (!res.ok && res.status !== 202) throw new McpError(`${method} rejected: HTTP ${res.status}`, { status: res.status });
    await res.body?.cancel().catch(() => {});
  }

  /** Read a POST response: a JSON object, or an SSE stream ending with our response. */
  async #readResponse(res, id, o, { modern }) {
    const type = res.headers.get("content-type") || "";
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      let msg = null;
      try {
        msg = JSON.parse(text);
      } catch {
        /* not JSON */
      }
      if (msg?.error) {
        throw new McpError(msg.error.message || `HTTP ${res.status}`, { code: msg.error.code, status: res.status, data: msg.error.data });
      }
      const hint = res.status === 401 ? " (authentication required: add an Authorization header in settings)" : res.status === 403 ? " (forbidden: the server may reject the extension's Origin)" : "";
      throw new McpError(`MCP server returned HTTP ${res.status}${hint}`, { status: res.status, data: text.slice(0, 300) });
    }
    if (/application\/json/i.test(type)) {
      const msg = await res.json().catch(() => null);
      return this.#unwrap(Array.isArray(msg) ? msg.find((m) => m.id === id) : msg, res.status);
    }
    if (/text\/event-stream/i.test(type)) {
      try {
        return await this.#readStream(res, id, o, modern);
      } catch (e) {
        if (e instanceof McpError) throw e;
        if (e.name === "TimeoutError") throw new McpError(`MCP server timed out after ${Math.round(this.timeoutMs / 1000)}s`);
        if (e.name === "AbortError") throw new McpError("Cancelled");
        throw new McpError(`Stream error: ${e.message}`);
      }
    }
    if (res.status === 202) return null;
    throw new McpError(`Unexpected response type "${type || "none"}"`, { status: res.status });
  }

  async #readStream(res, id, o, modern) {
  for await (const ev of readSse(res.body)) {
      if (ev.event !== "message" || !ev.data) continue;
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        continue;
      }
      for (const m of Array.isArray(msg) ? msg : [msg]) {
        if (m.id === id && ("result" in m || "error" in m)) return this.#unwrap(m, res.status);
        if (m.method && m.id !== undefined && !modern) await this.#answerServerRequest(m);
        else if (m.method === "notifications/progress") o.onProgress?.(m.params);
        else if (m.method === "notifications/message") o.onLog?.(m.params);
      }
    }
    throw new McpError("Stream ended without a response", { status: res.status });
  }

  #unwrap(msg, status) {
    if (!msg) throw new McpError("Empty response", { status });
    if (msg.error) {
      const e = new McpError(msg.error.message || "MCP error", { code: msg.error.code, status, data: msg.error.data });
      if (isModernErrorCode(msg.error.code)) e.modern = true;
      throw e;
    }
    return msg.result;
  }

  /** Answer a server-to-client request on a legacy stream (we only support ping). */
  async #answerServerRequest(m) {
    const reply = m.method === "ping" ? { jsonrpc: "2.0", id: m.id, result: {} } : { jsonrpc: "2.0", id: m.id, error: { code: -32601, message: `Client does not support ${m.method}` } };
    if (this.transport === "sse-2024") return this.#postSse(reply);
    await this.#fetch(this.url, { method: "POST", headers: this.#legacyHeaders(), body: JSON.stringify(reply) }).then((r) => r.body?.cancel()).catch(() => {});
  }

  // --- sse-2024 -----------------------------------------------------------

  #dispatchSse(data) {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }
    for (const m of Array.isArray(msg) ? msg : [msg]) {
      if (m.id !== undefined && ("result" in m || "error" in m)) {
        const p = this.ssePending.get(m.id);
        if (p) {
          this.ssePending.delete(m.id);
          if (m.error) p.reject(new McpError(m.error.message || "MCP error", { code: m.error.code, data: m.error.data }));
          else p.resolve(m.result);
        }
      } else if (m.method && m.id !== undefined) {
        this.#answerServerRequest(m);
      } else if (m.method === "notifications/progress") {
        for (const p of this.ssePending.values()) p.onProgress?.(m.params);
      }
    }
  }

  async #postSse(msg) {
    const res = await this.#fetch(this.sseEndpoint, { method: "POST", headers: { "content-type": "application/json", ...this.extraHeaders }, body: JSON.stringify(msg) });
    await res.body?.cancel().catch(() => {});
    if (!res.ok && res.status !== 202) throw new McpError(`SSE POST rejected: HTTP ${res.status}`, { status: res.status });
  }

  #rpcSse(method, params, o = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.ssePending.delete(id);
        reject(new McpError(`MCP server timed out after ${Math.round(this.timeoutMs / 1000)}s`));
      }, this.timeoutMs);
      const done = (fn) => (v) => {
        clearTimeout(timer);
        fn(v);
      };
      this.ssePending.set(id, { resolve: done(resolve), reject: done(reject), onProgress: o.onProgress });
      o.signal?.addEventListener("abort", () => {
        this.ssePending.delete(id);
        done(reject)(new McpError("Cancelled"));
      }, { once: true });
      this.#postSse({ jsonrpc: "2.0", id, method, params }).catch((e) => {
        this.ssePending.delete(id);
        done(reject)(e);
      });
    });
  }
}

/**
 * Render a CallToolResult as plain text (for the AI and for display).
 * Images and audio are summarised, not inlined.
 */
export function toolResultText(result, max = 20000) {
  if (!result) return "(no result)";
  const parts = [];
  for (const c of result.content || []) {
    if (c.type === "text") parts.push(c.text);
    else if (c.type === "image") parts.push(`[image ${c.mimeType}, ${Math.round((c.data?.length || 0) * 0.75 / 1024)} KB]`);
    else if (c.type === "audio") parts.push(`[audio ${c.mimeType}]`);
    else if (c.type === "resource_link") parts.push(`[resource link: ${c.name || ""} ${c.uri}]`);
    else if (c.type === "resource") parts.push(c.resource?.text ? `[resource ${c.resource.uri}]\n${c.resource.text}` : `[binary resource ${c.resource?.uri}]`);
  }
  if (!parts.length && result.structuredContent !== undefined) parts.push(JSON.stringify(result.structuredContent, null, 2));
  const text = parts.join("\n\n") || "(empty result)";
  return text.length > max ? `${text.slice(0, max)}\n…[truncated ${text.length - max} characters]` : text;
}
