// Follow-up jobs on a stored report: online lookups, AI analysis, file
// metadata, evidence capture, MCP tool calls and recipes. Each job updates the
// report in IndexedDB and reports progress through state.js.

import { getReport, putReport, putEvidence, correlate } from "../shared/db.js";
import { getSettings, saveSettings } from "../shared/settings.js";
import { enrich, addIndicator } from "../intel/enrich.js";
import { runAgent } from "../ai/agent.js";
import { builtinTools } from "../ai/tools.js";
import { aiTools, callTool, fillTemplate } from "../mcp/registry.js";
import { toolResultText } from "../mcp/client.js";
import { parseImageMetadata, sniffImage } from "../core/exif.js";
import { parseDocument, docRows } from "../core/docmeta.js";
import { digestHex, mapLimit, bytesToBase64 } from "../core/util.js";
import { fetchMany } from "./scan.js";
import { httpGet } from "../intel/http.js";
import { setJob, bumpReport, keepAlive, startCancellable, requestApproval, denyApprovals } from "./state.js";

async function mustGet(reportId) {
  const r = await getReport(reportId);
  if (!r) throw new Error("This report no longer exists (it may have been deleted from history).");
  return r;
}

/** Re-read, apply `fn`, write back: avoids lost updates when jobs overlap. */
async function update(reportId, fn) {
  const r = await mustGet(reportId);
  await fn(r);
  await putReport(r);
  await bumpReport(reportId);
  return r;
}

// ---------------------------------------------------------------------------
// Online lookups
// ---------------------------------------------------------------------------

export async function runOnline(reportId) {
  const settings = await getSettings();
  const { signal, done } = startCancellable(reportId, "online");
  await setJob(reportId, "online", { status: "running", step: "Starting", error: null });
  try {
    await keepAlive(async () => {
      const report = await mustGet(reportId);
      const enabled = Object.fromEntries(Object.entries(settings.online).filter(([, v]) => typeof v === "boolean"));
      await enrich(report, enabled, { signal, urlscanKey: settings.online.urlscanKey, onProgress: (step) => setJob(reportId, "online", { step }) });
      // Merge into the latest stored copy (other jobs may have written meanwhile).
      await update(reportId, async (r) => {
        r.online = report.online;
        r.phishing = report.phishing;
        r.trackers = report.trackers;
        for (const i of report.indicators) addIndicator(r, i.type, i.value, { label: i.label, source: i.sources[0], extra: i.extra, confidence: i.confidence });
        r.correlations = await correlate(r).catch(() => r.correlations || []);
      });
    });
    await setJob(reportId, "online", { status: "done", step: null });
  } catch (e) {
    await setJob(reportId, "online", { status: signal.aborted ? "cancelled" : "error", error: e.message, step: null });
  } finally {
    done();
  }
}

// ---------------------------------------------------------------------------
// AI
// ---------------------------------------------------------------------------

/**
 * @param {string} reportId
 * @param {{mode:string, question?:string, followUp?:boolean}} o
 */
export async function runAi(reportId, o) {
  const settings = await getSettings();
  const { signal, done } = startCancellable(reportId, "ai");
  const events = [];
  const push = async (e) => {
    if (e.type === "tool") {
      const i = events.findIndex((x) => x.type === "tool" && x.entry.id === e.entry.id);
      if (i >= 0) events[i] = e;
      else events.push(e);
    } else if (e.type === "thinking") {
      const i = events.findIndex((x) => x.type === "thinking");
      if (i >= 0) events.splice(i, 1);
      events.push(e);
    } else events.push(e);
    await setJob(reportId, "ai", { events: events.slice(-40) });
  };
  await setJob(reportId, "ai", { status: "running", error: null, events: [], mode: o.mode, followUp: !!o.followUp });
  try {
    await keepAlive(async () => {
      const report = await mustGet(reportId);
      const mcpResults = [];
      const { tools: mcpTools, errors: mcpErrors } = settings.ai.useTools ? await aiTools(settings, { signal, onResult: (r) => mcpResults.push(r) }) : { tools: [], errors: [] };
      for (const err of mcpErrors) await push({ type: "status", text: `MCP server unavailable: ${err}` });
      const tools = settings.ai.useTools ? [...builtinTools(report, settings.online), ...mcpTools] : [];

      const approve = async (call) => {
        const tool = tools.find((t) => t.name === call.tool);
        if (!tool || !tool.serverId || !tool.needsApproval) return true;
        const decision = await requestApproval({ reportId, server: tool.source, serverId: tool.serverId, tool: tool.mcpTool, args: call.args, readOnly: tool.readOnly });
        if (decision === "always") {
          const s = await getSettings();
          const srv = s.mcp.servers.find((x) => x.id === tool.serverId);
          if (srv) {
            srv.allowedTools = [...new Set([...(srv.allowedTools || []), tool.mcpTool])];
            await saveSettings(s);
          }
        }
        return decision === "allow" || decision === "always";
      };

      const history = o.followUp ? report.ai?.messages || [] : null;
      if (o.followUp && !history.length) throw new Error("Run an analysis first, then ask follow-up questions.");
      const out = await runAgent({ report, settings, mode: o.mode, question: o.question, history, tools, approve, onEvent: push, signal });

      await update(reportId, (r) => {
        r.ai ||= {};
        const now = new Date().toISOString();
        if (o.followUp) {
          r.ai.followUps = [...(r.ai.followUps || []), { question: o.question, answer: out.answer, at: now, log: out.log }];
        } else {
          Object.assign(r.ai, { mode: o.mode, question: o.question || null, result: out.result, raw: out.raw, log: out.log, model: out.model, local: out.local, at: now, followUps: [] });
        }
        r.ai.messages = out.messages.slice(-60);
        for (const m of mcpResults) r.mcp = [...(r.mcp || []), { server: m.server, serverId: m.serverId, tool: m.tool, args: m.args, isError: !!m.result?.isError, text: toolResultText(m.result, 8000), images: imagesOf(m.result), at: now, by: "ai" }].slice(-50);
        // Entities the model identified become indicators (marked as AI-derived).
        for (const e of out.result?.entities || []) {
          const map = { person: "person", organization: "organization", email: "email", phone: "phone", wallet: "crypto", domain: "domain", ip: "ip", account: "handle" };
          const type = map[e.type];
          if (type && e.value && String(e.value).length < 200) addIndicator(r, type, String(e.value).trim(), { source: "AI analysis", confidence: "low", extra: { note: e.note || null } });
        }
      });
    });
    await setJob(reportId, "ai", { status: "done" });
  } catch (e) {
    await setJob(reportId, "ai", { status: signal.aborted ? "cancelled" : "error", error: e.message });
  } finally {
    await denyApprovals(reportId);
    done();
  }
}

const imagesOf = (result) => (result?.content || []).filter((c) => c.type === "image" && c.data && c.data.length < 3e6).slice(0, 4).map((c) => ({ mimeType: c.mimeType, data: c.data }));

// ---------------------------------------------------------------------------
// File metadata (images and documents)
// ---------------------------------------------------------------------------

export async function runFiles(reportId, urls, tabId) {
  const { signal, done } = startCancellable(reportId, "files");
  await setJob(reportId, "files", { status: "running", done: 0, total: urls.length, error: null });
  try {
    await keepAlive(async () => {
      const report = await mustGet(reportId);
      const origin = new URL(report.page.url).origin;
      const tabOk = tabId != null && (await chrome.tabs.get(tabId).then((t) => t.url && new URL(t.url).origin === origin).catch(() => false));
      let n = 0;
      const results = await mapLimit(urls.slice(0, 200), 4, async (url) => {
        if (signal.aborted) return null;
        const entry = { url, analyzedAt: new Date().toISOString() };
        try {
          let r;
          if (tabOk) r = (await fetchMany(tabId, origin, [{ url, binary: true, maxBytes: 25e6 }])).get(url);
          else {
            const res = await httpGet(url, { as: "bytes", maxBytes: 25e6, timeoutMs: 60000, signal }).catch((e) => ({ error: /reach/.test(e.message) ? "no permission" : e.message }));
            r = res.bytes ? { ok: true, status: res.status, bytes: res.bytes, headers: Object.fromEntries(res.headers) } : res;
          }
          if (!r?.ok || !r.bytes) throw new Error(r?.error === "no permission" ? "needs access to that site (grant it in the Files tab)" : r?.status ? `HTTP ${r.status}` : r?.error || "couldn't download");
          const bytes = r.bytes;
          entry.size = bytes.length;
          entry.sha256 = await digestHex("SHA-256", bytes);
          entry.contentType = r.headers?.["content-type"] || null;
          entry.lastModified = r.headers?.["last-modified"] || null;
          const kind = sniffImage(bytes);
          if (!["unknown", "svg/xml"].includes(kind)) {
            const m = await parseImageMetadata(bytes);
            Object.assign(entry, { kind: "image", format: m.format, rows: m.fields, gps: m.gps });
          } else {
            const d = await parseDocument(bytes);
            if (d) Object.assign(entry, { kind: "document", format: d.format, rows: docRows(d), warnings: d.warnings || [], authors: d.authors || [], users: d.users || [] });
            else Object.assign(entry, { kind: "other", format: kind, rows: [] });
          }
        } catch (e) {
          entry.error = e.message;
        }
        n++;
        await setJob(reportId, "files", { done: n });
        return entry;
      });
      await update(reportId, (r) => {
        const map = new Map((r.files || []).map((f) => [f.url, f]));
        for (const f of results.filter(Boolean)) map.set(f.url, f);
        r.files = [...map.values()];
        for (const f of results.filter(Boolean)) {
          if (f.gps) addIndicator(r, "coordinates", `${f.gps.lat}, ${f.gps.lon}`, { source: `EXIF GPS in ${f.url.split("/").pop()}`, extra: { lat: f.gps.lat, lon: f.gps.lon } });
          for (const a of f.authors || []) addIndicator(r, "person", a, { source: `metadata of ${f.url.split("/").pop()}`, confidence: "medium" });
          for (const u of f.users || []) addIndicator(r, "handle", u, { source: `file path in ${f.url.split("/").pop()}`, label: "OS user name", confidence: "medium" });
          for (const row of f.rows || []) {
            if (/^(Company|Credit|Copyright|Manager)$/.test(row.name) && row.value.length < 120) addIndicator(r, "organization", row.value.replace(/^\(c\)\s*|^©\s*/i, ""), { source: `metadata of ${f.url.split("/").pop()}`, confidence: "medium" });
            if (/^(Artist|XPAuthor|CameraOwnerName|By-line|creator|OwnerName)$/.test(row.name) && row.value.length < 120) addIndicator(r, "person", row.value, { source: `metadata of ${f.url.split("/").pop()}`, confidence: "medium" });
          }
          if (f.sha256) addIndicator(r, "hash", f.sha256, { source: f.url, label: "SHA-256", confidence: "medium" });
        }
      });
    });
    await setJob(reportId, "files", { status: "done" });
  } catch (e) {
    await setJob(reportId, "files", { status: "error", error: e.message });
  } finally {
    done();
  }
}

// ---------------------------------------------------------------------------
// Evidence capture
// ---------------------------------------------------------------------------

export async function captureEvidence(reportId, tabId, kind) {
  await setJob(reportId, "evidence", { status: "running", error: null });
  try {
    const tab = await chrome.tabs.get(tabId);
    const report = await mustGet(reportId);
    let bytes, mime, ext;
    if (kind === "mhtml") {
      const blob = await chrome.pageCapture.saveAsMHTML({ tabId });
      bytes = new Uint8Array(await blob.arrayBuffer());
      mime = "multipart/related";
      ext = "mhtml";
    } else {
      const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
      bytes = Uint8Array.from(atob(dataUrl.split(",")[1]), (c) => c.charCodeAt(0));
      mime = "image/png";
      ext = "png";
    }
    const sha256 = await digestHex("SHA-256", bytes);
    const item = { id: `ev_${Date.now().toString(36)}`, reportId, kind, mime, ext, size: bytes.length, sha256, url: tab.url, title: tab.title, capturedAt: new Date().toISOString(), data: bytesToBase64(bytes), reportUrl: report.page.url };
    await putEvidence(item);
    await update(reportId, (r) => {
      r.evidence = [...(r.evidence || []), { id: item.id, kind, ext, size: item.size, sha256, url: item.url, capturedAt: item.capturedAt }];
    });
    await setJob(reportId, "evidence", { status: "done" });
    return { id: item.id, sha256 };
  } catch (e) {
    await setJob(reportId, "evidence", { status: "error", error: e.message });
    throw e;
  }
}

// ---------------------------------------------------------------------------
// MCP tool calls run by the user (and recipes)
// ---------------------------------------------------------------------------

export async function runMcpTool(reportId, serverId, tool, args, by = "user") {
  const settings = await getSettings();
  const server = settings.mcp.servers.find((s) => s.id === serverId);
  if (!server) throw new Error("That MCP server is no longer configured.");
  const { signal, done } = startCancellable(reportId, `mcp:${serverId}:${tool}`);
  await setJob(reportId, "mcp", { status: "running", tool: `${server.name} / ${tool}`, error: null });
  try {
    const result = await keepAlive(() => callTool(server, tool, args, { signal }));
    const entry = { server: server.name, serverId, tool, args, isError: !!result?.isError, text: toolResultText(result, 20000), images: imagesOf(result), structured: result?.structuredContent ?? null, at: new Date().toISOString(), by };
    await update(reportId, (r) => {
      r.mcp = [...(r.mcp || []), entry].slice(-50);
    });
    await setJob(reportId, "mcp", { status: "done" });
    return entry;
  } catch (e) {
    await setJob(reportId, "mcp", { status: "error", error: e.message });
    throw e;
  } finally {
    done();
  }
}

export async function runRecipe(reportId, recipeId) {
  const settings = await getSettings();
  const recipe = settings.recipes.find((r) => r.id === recipeId);
  if (!recipe) throw new Error("Recipe not found.");
  const report = await mustGet(reportId);
  const args = fillTemplate(recipe.args, report);
  return runMcpTool(reportId, recipe.serverId, recipe.tool, args, `recipe: ${recipe.name}`);
}

export async function runAutoRecipes(reportId) {
  const settings = await getSettings();
  for (const r of settings.recipes.filter((x) => x.auto)) {
    const server = settings.mcp.servers.find((s) => s.id === r.serverId);
    if (!server?.enabled) continue;
    await runRecipe(reportId, r.id).catch(() => {});
  }
}
