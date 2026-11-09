// Background service worker: message router, side panel and context menus.
// All long-running work happens here, not in the side panel, so closing the
// panel never cancels a scan or an AI analysis.

import { scanTab, NoAccessError } from "./scan.js";
import { runOnline, runAi, runFiles, captureEvidence, runMcpTool, runRecipe, runAutoRecipes } from "./jobs.js";
import { setTabState, getTabState, clearTabState, resolveApproval, cancel, denyApprovals, bumpReport } from "./state.js";
import { getSettings } from "../shared/settings.js";
import { getReport, putReport, deleteReport, listReports, clearAll } from "../shared/db.js";
import { inspectServer, dropClient } from "../mcp/registry.js";
import { PROVIDERS } from "../ai/providers.js";

const running = new Set();

// --- Install / startup -----------------------------------------------------------

async function setup() {
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({ id: "scan-page", title: "Scan this page with OSINT Lens", contexts: ["page", "frame"] });
  chrome.contextMenus.create({ id: "investigate-selection", title: 'Investigate "%s"', contexts: ["selection"] });
  chrome.contextMenus.create({ id: "investigate-link", title: "Investigate this link", contexts: ["link"] });
  chrome.contextMenus.create({ id: "investigate-image", title: "Check this image's metadata", contexts: ["image"] });
}

chrome.runtime.onInstalled.addListener((d) => {
  setup();
  if (d.reason === "install") chrome.tabs.create({ url: chrome.runtime.getURL("src/ui/welcome.html") });
});
chrome.runtime.onStartup.addListener(setup);

// --- Context menus -----------------------------------------------------------------

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  // open() must be called synchronously within the user gesture.
  chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
  if (info.menuItemId === "scan-page") return startScan(tab.id);
  const query = info.menuItemId === "investigate-selection" ? info.selectionText : info.menuItemId === "investigate-link" ? info.linkUrl : info.srcUrl;
  await chrome.storage.session.set({ [`query:${tab.windowId}`]: { text: String(query || "").slice(0, 2000), kind: String(info.menuItemId), tabId: tab.id, at: Date.now() } });
  if (info.menuItemId === "investigate-image" && info.srcUrl) {
    const st = await getTabState(tab.id);
    if (st?.reportId) runFiles(st.reportId, [info.srcUrl], tab.id);
  }
});

chrome.commands?.onCommand.addListener(async (cmd, tab) => {
  if (cmd === "scan-page" && tab?.id) startScan(tab.id);
});

// --- Tab lifecycle -------------------------------------------------------------------

chrome.tabs.onUpdated.addListener(async (tabId, info) => {
  if (info.status !== "loading" || running.has(tabId)) return;
  const st = await getTabState(tabId);
  // Keep the last report reachable but mark it as belonging to a previous page.
  if (st?.reportId) await setTabState(tabId, { stale: true });
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const st = await getTabState(tabId);
  await clearTabState(tabId);
  const settings = await getSettings();
  if (!settings.privacy.keepHistory && st?.reportId) {
    const r = await getReport(st.reportId).catch(() => null);
    if (r && !r.starred) await deleteReport(st.reportId).catch(() => {});
  }
});

// --- Scans ------------------------------------------------------------------------------

async function startScan(tabId) {
  if (running.has(tabId)) return { started: false, reason: "already running" };
  running.add(tabId);
  (async () => {
    try {
      const report = await scanTab(tabId);
      await setTabState(tabId, { stale: false });
      const settings = await getSettings();
      if (settings.scan.autoOnline) await runOnline(report.id);
      if (settings.recipes.some((r) => r.auto)) await runAutoRecipes(report.id);
      if (settings.ai.autoRun) await runAi(report.id, { mode: "osint" });
    } catch (e) {
      await setTabState(tabId, { status: "error", step: null, error: e.message, errorCode: e instanceof NoAccessError ? "no_access" : null, errorUrl: e.url || null });
    } finally {
      running.delete(tabId);
    }
  })();
  return { started: true };
}

// --- Messages from the side panel and options page ---------------------------------------

const handlers = {
  scan: ({ tabId }) => startScan(tabId),
  online: ({ reportId }) => (runOnline(reportId), { started: true }),
  ai: ({ reportId, mode, question }) => (runAi(reportId, { mode, question }), { started: true }),
  followUp: ({ reportId, question }) => (runAi(reportId, { mode: "followup", question, followUp: true }), { started: true }),
  files: ({ reportId, urls, tabId }) => (runFiles(reportId, urls, tabId), { started: true }),
  cancel: async ({ reportId, slot }) => {
    cancel(reportId, slot);
    if (slot === "ai") await denyApprovals(reportId);
    return { ok: true };
  },
  approval: ({ id, decision }) => ({ ok: resolveApproval(id, decision) }),
  evidence: ({ reportId, tabId, kind }) => captureEvidence(reportId, tabId, kind),
  mcpTool: ({ reportId, serverId, tool, args }) => runMcpTool(reportId, serverId, tool, args),
  recipe: ({ reportId, recipeId }) => runRecipe(reportId, recipeId),
  mcpInspect: async ({ server }) => {
    dropClient(server.id);
    return inspectServer(server);
  },
  aiModels: async ({ provider, cfg }) => {
    const p = PROVIDERS[provider];
    if (!p) throw new Error(`Unknown provider ${provider}`);
    const models = await p.models(cfg);
    const caps = provider === "ollama" && cfg.model ? await p.capabilities(cfg, cfg.model) : null;
    return { models, capabilities: caps };
  },
  updateReport: async ({ reportId, patch }) => {
    const r = await getReport(reportId);
    if (!r) throw new Error("Report not found");
    for (const k of ["notes", "tags", "starred", "title"]) if (k in patch) r[k] = patch[k];
    await putReport(r);
    await bumpReport(reportId);
    return { ok: true };
  },
  deleteReport: async ({ reportId }) => {
    await deleteReport(reportId);
    return { ok: true };
  },
  clearHistory: async () => {
    await clearAll();
    return { ok: true };
  },
  listReports: ({ limit }) => listReports(limit)
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own pages may drive the extension.
  if (sender.id !== chrome.runtime.id || (sender.url && !sender.url.startsWith(chrome.runtime.getURL("")))) return false;
  const h = handlers[msg?.type];
  if (!h) return false;
  Promise.resolve()
    .then(() => h(msg))
    .then((result) => sendResponse({ ok: true, result }), (e) => sendResponse({ ok: false, error: e?.message || String(e) }));
  return true;
});
