// MCP servers configured by the user: connections, tool lists, approval policy.
// Runs in the service worker.

import { McpClient, toolResultText } from "./client.js";

const clients = new Map(); // serverId -> { key, client }

const headersOf = (server) => Object.fromEntries((server.headers || []).filter((h) => h.name && h.value).map((h) => [h.name.trim(), h.value]));
const configKey = (s) => JSON.stringify([s.url, s.transport, s.headers]);

export function getClient(server) {
  const key = configKey(server);
  const cur = clients.get(server.id);
  if (cur && cur.key === key) return cur.client;
  cur?.client.close().catch(() => {});
  const client = new McpClient({ url: server.url, transport: server.transport || "auto", headers: headersOf(server), timeoutMs: (server.timeoutSec || 120) * 1000 });
  clients.set(server.id, { key, client });
  return client;
}

export function dropClient(serverId) {
  clients.get(serverId)?.client.close().catch(() => {});
  clients.delete(serverId);
}

/** Connect and list tools/resources/prompts. Caches the result in storage for the UI. */
export async function inspectServer(server) {
  const client = getClient(server);
  try {
    const info = await client.connect();
    const caps = info.capabilities || {};
    const [tools, resources, prompts] = await Promise.all([
      client.listTools().catch((e) => (caps.tools ? Promise.reject(e) : [])),
      caps.resources ? client.listResources().catch(() => []) : [],
      caps.prompts ? client.listPrompts().catch(() => []) : []
    ]);
    const entry = { ok: true, info, tools, resources, prompts, at: Date.now() };
    await chrome.storage.local.set({ [`mcpCache:${server.id}`]: entry });
    return entry;
  } catch (e) {
    dropClient(server.id);
    const entry = { ok: false, error: e.message || String(e), at: Date.now() };
    await chrome.storage.local.set({ [`mcpCache:${server.id}`]: entry });
    return entry;
  }
}

export async function cachedServer(serverId) {
  const k = `mcpCache:${serverId}`;
  return (await chrome.storage.local.get(k))[k] || null;
}

/** Tool list, from cache when fresh (10 min), otherwise from the server. */
export async function serverTools(server) {
  const c = await cachedServer(server.id);
  if (c?.ok && Date.now() - c.at < 600000) return c.tools;
  const fresh = await inspectServer(server);
  if (!fresh.ok) throw new Error(`${server.name}: ${fresh.error}`);
  return fresh.tools;
}

export async function callTool(server, name, args, o = {}) {
  const client = getClient(server);
  try {
    return await client.callTool(name, args, o);
  } catch (e) {
    // One reconnect attempt: the service worker may have been restarted, or the server restarted.
    if (/Cancelled/.test(e.message)) throw e;
    dropClient(server.id);
    return getClient(server).callTool(name, args, o);
  }
}

/** Does this call need the user's OK? */
export function needsApproval(server, tool) {
  if (server.approval === "always") return false;
  if ((server.allowedTools || []).includes(tool.name)) return false;
  if (server.approval === "readonly" && tool.annotations?.readOnlyHint === true) return false;
  return true;
}

/** MCP tools offered to the AI, as agent tool objects. */
export async function aiTools(settings, o = {}) {
  const out = [];
  const errors = [];
  for (const server of settings.mcp.servers.filter((s) => s.enabled && s.useInAi)) {
    let tools;
    try {
      tools = await serverTools(server);
    } catch (e) {
      errors.push(e.message);
      continue;
    }
    for (const t of tools) {
      if ((server.disabledTools || []).includes(t.name)) continue;
      out.push({
        name: `${server.name}_${t.name}`,
        description: t.description || t.title || t.annotations?.title || t.name,
        parameters: t.inputSchema,
        readOnly: t.annotations?.readOnlyHint === true,
        source: server.name,
        serverId: server.id,
        mcpTool: t.name,
        needsApproval: needsApproval(server, t),
        run: async (args, ctx) => {
          const r = await callTool(server, t.name, args, { signal: ctx?.signal || o.signal });
          o.onResult?.({ server: server.name, serverId: server.id, tool: t.name, args, result: r });
          return `${r?.isError ? "TOOL REPORTED AN ERROR:\n" : ""}${toolResultText(r)}`;
        }
      });
    }
  }
  return { tools: out, errors };
}

/**
 * Fill a recipe's argument template from a report.
 * Placeholders: {url} {host} {domain} {title} {ip} (first resolved IP) {email} (first email)
 */
export function fillTemplate(template, report) {
  const first = (type) => report.indicators.find((i) => i.type === type && !i.extra?.private)?.value || "";
  const vars = { url: report.page.url, host: report.page.host, domain: report.page.site, title: report.page.title || "", ip: first("ip"), email: first("email") };
  const fill = (v) => (typeof v === "string" ? v.replace(/\{(url|host|domain|title|ip|email)\}/g, (_, k) => vars[k]) : Array.isArray(v) ? v.map(fill) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v);
  let parsed;
  try {
    parsed = typeof template === "string" ? JSON.parse(template || "{}") : template || {};
  } catch {
    throw new Error("The recipe's arguments aren't valid JSON.");
  }
  return fill(parsed);
}
