// Side panel controller: tracks the active tab, watches scan/job state in
// chrome.storage.session, loads reports from IndexedDB and renders the views.

import { h, clear, send, toast, menu, download, fileStem, ago, sev } from "./dom.js";
import { getReport } from "../shared/db.js";
import { getSettings } from "../shared/settings.js";
import { pivotsFor } from "../core/pivots.js";
import { toJson, toMarkdown, toCsv, toStix } from "../core/export.js";
import { oslHighlight } from "../content/highlight.js";
import * as overview from "./tabs/overview.js";
import * as indicators from "./tabs/indicators.js";
import * as exposures from "./tabs/exposures.js";
import * as infra from "./tabs/infra.js";
import * as tech from "./tabs/tech.js";
import * as links from "./tabs/links.js";
import * as files from "./tabs/files.js";
import * as ai from "./tabs/ai.js";
import * as mcp from "./tabs/mcp.js";
import * as history from "./history.js";
import * as lookup from "./lookup.js";

const TABS = [
  ["overview", "Overview", overview],
  ["indicators", "Indicators", indicators],
  ["exposures", "Exposures", exposures],
  ["infra", "Infrastructure", infra],
  ["tech", "Tech & trackers", tech],
  ["links", "Links & forms", links],
  ["files", "Files", files],
  ["ai", "AI", ai],
  ["mcp", "MCP", mcp]
];

const S = {
  windowId: null,
  tabId: null,
  tabState: null,
  report: null,
  reportId: null,
  pinnedReportId: null, // a report opened from History (not tied to the current tab)
  job: {},
  approvals: {},
  settings: null,
  view: "report", // "report" | "history" | "lookup"
  tab: "overview",
  reveal: false,
  hl: new Map(), // id -> highlight item
  hlCounts: {},
  hlFocus: null,
  ui: {} // per-tab transient UI state (filters, form values)
};

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// Context handed to tab modules
// ---------------------------------------------------------------------------

const ctx = {
  S,
  send,
  rerender: () => renderContent(),
  setTab: (t) => {
    S.tab = t;
    S.view = "report";
    renderAll();
  },
  isCurrentTab: () => !S.pinnedReportId && S.tabState?.reportId === S.report?.id && !S.tabState?.stale,
  pivotMenu(btn, ind) {
    const items = pivotsFor(ind).map((p) => ({ label: p.name, href: p.url }));
    items.push({ label: "Copy value", onclick: () => navigator.clipboard.writeText(ind.value) });
    if (S.settings?.mcp.servers.some((s) => s.enabled)) items.push({ label: "Send to an MCP tool…", onclick: () => ctx.openMcp(ind) });
    items.push({ label: "Ask the AI about this…", onclick: () => ctx.askAi(`What can you find out about ${ind.type} "${ind.value}" and how does it relate to this site?`) });
    menu(btn, items);
  },
  openMcp(ind) {
    S.ui.mcpPrefill = ind;
    ctx.setTab("mcp");
  },
  askAi(question) {
    S.ui.aiQuestion = question;
    ctx.setTab("ai");
  },
  async highlight(id, item, { focus = false, toggle = false } = {}) {
    if (!ctx.isCurrentTab()) return toast("Highlighting works on the page that was scanned. Scan again first.", "error");
    if (toggle && S.hl.has(id) && !focus) S.hl.delete(id);
    else S.hl.set(id, { id, ...item });
    let focusArg = null;
    if (focus) {
      const idx = S.hlFocus?.id === id ? S.hlFocus.index + 1 : 0;
      focusArg = { id, index: idx };
    }
    try {
      const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: S.tabId }, func: oslHighlight, args: [{ action: S.hl.size ? "set" : "clear", items: [...S.hl.values()], focus: focusArg, scroll: !!focusArg }] });
      S.hlCounts = result?.counts || {};
      S.hlFocus = result?.focus || (focus ? null : S.hlFocus);
      if (focus && !result?.focus) toast("Not visible on the page (hidden text, inside a frame, or the page changed).");
      return result;
    } catch (e) {
      toast(`Can't highlight on this page: ${e.message}`, "error");
    }
  },
  async clearHighlights() {
    S.hl.clear();
    S.hlFocus = null;
    S.hlCounts = {};
    if (S.tabId != null) await chrome.scripting.executeScript({ target: { tabId: S.tabId }, func: oslHighlight, args: [{ action: "clear", items: [] }] }).catch(() => {});
  },
  async requestHostAccess(origins) {
    try {
      const ok = await chrome.permissions.request({ origins });
      if (!ok) toast("Access not granted.");
      return ok;
    } catch (e) {
      toast(e.message, "error");
      return false;
    }
  },
  openReport(id) {
    S.pinnedReportId = id;
    S.view = "report";
    S.tab = "overview";
    loadReport(id);
  }
};

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

// "Pop out" mode: the panel opened as a full tab, bound to one inspected tab (?tabId=…).
const BOUND_TAB = Number(new URLSearchParams(location.search).get("tabId")) || null;

async function refreshTab() {
  const tab = BOUND_TAB ? await chrome.tabs.get(BOUND_TAB).catch(() => null) : (await chrome.tabs.query({ active: true, windowId: S.windowId }))[0];
  if (!tab) {
    if (BOUND_TAB) clear($("content")).append(h("div.notice.error", "The inspected tab was closed."));
    return;
  }
  const changed = tab.id !== S.tabId;
  S.tabId = tab.id;
  S.tabUrl = tab.url || null;
  S.tabState = (await chrome.storage.session.get(`tab:${tab.id}`))[`tab:${tab.id}`] || null;
  if (changed) {
    S.hl.clear();
    S.hlFocus = null;
    S.pinnedReportId = null;
  }
  if (!S.pinnedReportId) await loadReport(S.tabState?.reportId || null);
  else renderAll();
}

async function loadReport(id) {
  S.reportId = id;
  S.report = id ? await getReport(id).catch(() => null) : null;
  S.job = id ? (await chrome.storage.session.get(`job:${id}`))[`job:${id}`] || {} : {};
  renderAll();
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderAll() {
  renderTabbar();
  renderLive();
  renderContent();
  $("scan-btn").textContent = S.tabState?.status === "running" ? "Scanning…" : S.report && ctx.isCurrentTab() ? "Scan again" : "Scan page";
  $("scan-btn").disabled = S.tabState?.status === "running";
  for (const [id, view] of [["history-btn", "history"], ["lookup-btn", "lookup"]]) $(id).classList.toggle("active", S.view === view);
}

function tabCount(id) {
  const r = S.report;
  if (!r) return null;
  if (id === "indicators") return r.indicators.length;
  if (id === "exposures") return r.exposures.length || null;
  if (id === "files") return r.files?.length || null;
  if (id === "mcp") return r.mcp?.length || null;
  return null;
}

function renderTabbar() {
  const bar = clear($("tabbar"));
  bar.classList.toggle("hidden", S.view !== "report" || !S.report);
  for (const [id, label] of TABS) {
    const n = tabCount(id);
    bar.append(h("button", { type: "button", class: S.tab === id ? "active" : "", onclick: () => ctx.setTab(id) }, label, n != null ? h("span.count", String(n)) : null));
  }
}

/** Status, errors and approval prompts: re-rendered on every state change. */
function renderLive() {
  const live = clear($("live"));
  const st = S.tabState;
  if (S.view === "report") {
    if (S.pinnedReportId && S.report) {
      live.append(h("div.notice.info", h("div.grow", "Viewing a saved report from ", h("b", ago(S.report.createdAt)), "."), h("button.btn.small", { type: "button", onclick: () => { S.pinnedReportId = null; refreshTab(); } }, "Back to current tab")));
    } else if (st?.status === "running") {
      live.append(h("div.notice", h("div.spin"), h("div.grow", st.step || "Working…")));
    } else if (st?.status === "error") {
      const box = h("div.notice.error", h("div.grow", h("b", "Scan failed. "), st.error));
      if (st.errorCode === "no_access") {
        let origin = null;
        try {
          origin = new URL(st.errorUrl).origin;
        } catch {
          /* ignore */
        }
        box.append(h("div.row.wrap-row", { style: { marginTop: "6px" } },
          origin ? h("button.btn.small.primary", { type: "button", onclick: async () => (await ctx.requestHostAccess([`${origin}/*`])) && startScan() }, "Allow on this site") : null,
          h("button.btn.small", { type: "button", onclick: async () => (await ctx.requestHostAccess(["http://*/*", "https://*/*"])) && startScan() }, "Allow on all sites")
        ));
        box.append(h("p.small.muted", "Or click the OSINT Lens toolbar icon on the page: that grants one-time access to the current tab."));
      }
      live.append(box);
    } else if (st?.stale && S.report && !S.pinnedReportId) {
      live.append(h("div.notice.warn", h("div.grow", "The page has changed since this report was made."), h("button.btn.small", { type: "button", onclick: startScan }, "Scan again")));
    }
  }
  // Pending tool approvals for this report.
  for (const a of Object.values(S.approvals || {})) {
    if (S.report && a.reportId !== S.report.id) continue;
    live.append(h("div.approval",
      h("div", h("b", "The AI wants to call an MCP tool")),
      h("div.small", "Server: ", h("b", a.server), " · Tool: ", h("b", a.tool), a.readOnly ? h("span.badge.good", " read-only") : h("span.badge.warn", "may modify data")),
      h("pre", JSON.stringify(a.args, null, 2)),
      h("div.small.muted", "Check the arguments: tools can send data to other services. Page content can try to trick the AI into misusing tools."),
      h("div.row.wrap-row",
        h("button.btn.small.primary", { type: "button", onclick: () => send("approval", { id: a.id, decision: "allow" }) }, "Allow once"),
        h("button.btn.small", { type: "button", onclick: () => send("approval", { id: a.id, decision: "always" }) }, "Always allow this tool"),
        h("button.btn.small.danger", { type: "button", onclick: () => send("approval", { id: a.id, decision: "deny" }) }, "Deny")
      )
    ));
  }
  // Tab-specific live areas (progress of AI, files, MCP).
  const mod = TABS.find(([id]) => id === S.tab)?.[2];
  const area = document.querySelector("[data-live]");
  if (area && mod?.live && S.view === "report" && S.report) area.replaceWith(mod.live(ctx));
}

function renderContent() {
  const content = clear($("content"));
  window.scrollTo(0, 0);
  if (S.view === "history") return content.append(history.render(ctx));
  if (S.view === "lookup") return content.append(lookup.render(ctx));
  if (!S.report) return content.append(welcome());
  content.append(summaryCard());
  const mod = TABS.find(([id]) => id === S.tab)?.[2] || overview;
  try {
    content.append(mod.render(ctx));
  } catch (e) {
    console.error(e);
    content.append(h("div.notice.error", `Couldn't render this section: ${e.message}`));
  }
}

function welcome() {
  const st = S.tabState;
  return h("div.card",
    h("h2", { style: { fontSize: "15px", marginBottom: "6px" } }, "Investigate this page"),
    h("p.muted", "Scan the page to extract identifiers (emails, phones, wallets, social profiles, tracking and ad IDs), infrastructure, technologies, exposed secrets and metadata, and to triage phishing. Online lookups, AI analysis and MCP tools build on the scan."),
    st?.status === "running" ? null : h("div.actions", { style: { marginTop: "8px" } }, h("button.btn.primary", { type: "button", onclick: startScan }, "Scan this page")),
    h("p.small.faint", { style: { marginTop: "10px" } }, "Scanning reads the page and the site's public files (robots.txt, security.txt, scripts). Nothing is sent to third parties unless you run online lookups, a cloud AI provider or an MCP tool.")
  );
}

function summaryCard() {
  const r = S.report;
  const p = r.page;
  const job = S.job || {};
  const chip = (label, n, tab, cls = "") => h(`button.chip${cls ? `.${cls}` : ""}`, { type: "button", onclick: () => ctx.setTab(tab) }, h("b", String(n)), label);
  const ph = r.phishing;
  const sevCounts = r.exposures.reduce((o, e) => ((o[e.severity] = (o[e.severity] || 0) + 1), o), {});
  const onlineBtn = h("button.btn.small", { type: "button", disabled: job.online?.status === "running", onclick: () => send("online", { reportId: r.id }).catch((e) => toast(e.message, "error")) },
    job.online?.status === "running" ? [h("span.spin"), job.online.step || "Looking up…"] : r.online ? "Re-run online lookups" : "Online lookups");
  const aiBtn = h("button.btn.small", { type: "button", onclick: () => ctx.setTab("ai") }, job.ai?.status === "running" ? [h("span.spin"), "AI working…"] : r.ai?.result ? "AI analysis ✓" : "AI analysis");

  const exportBtn = h("button.btn.small", { type: "button" }, "Export ▾");
  exportBtn.addEventListener("click", () => menu(exportBtn, [
    { label: "Markdown report (.md)", onclick: () => download(`${fileStem(p.host)}-osint.md`, toMarkdown(r), "text/markdown") },
    { label: "Full data (.json)", onclick: () => download(`${fileStem(p.host)}-osint.json`, toJson(r), "application/json") },
    { label: "Indicators (.csv)", onclick: () => download(`${fileStem(p.host)}-indicators.csv`, toCsv(r), "text/csv") },
    { label: "STIX 2.1 bundle (.json)", onclick: async () => download(`${fileStem(p.host)}-stix.json`, await toStix(r), "application/json") },
    { label: "Copy Markdown to clipboard", onclick: () => navigator.clipboard.writeText(toMarkdown(r)).then(() => toast("Copied")) }
  ]));
  const evBtn = h("button.btn.small", { type: "button", disabled: !ctx.isCurrentTab() || job.evidence?.status === "running", title: "Capture evidence of the page as it is now, with a SHA-256 hash" }, job.evidence?.status === "running" ? [h("span.spin"), "Capturing…"] : "Evidence ▾");
  evBtn.addEventListener("click", () => menu(evBtn, [
    { label: "Screenshot (visible area, PNG)", onclick: () => capture("screenshot") },
    { label: "Full page archive (MHTML)", onclick: () => capture("mhtml") }
  ]));

  return h("div.card.summary",
    h("div.title-row",
      r.favicon?.url ? h("img.fav", { src: r.favicon.url, alt: "", referrerpolicy: "no-referrer" }) : h("div.fav"),
      h("div.grow",
        h("div.page-title.wrap", p.title || p.host),
        h("div.page-url.wrap", p.url),
        p.unicodeHost ? h("div.small", h("span.badge.bad", "IDN"), " displays as ", h("b", p.unicodeHost)) : null
      )
    ),
    ph ? h(`div.risk.${ph.level}`,
      h("div.score", String(ph.score)),
      h("div.grow", h("div", h("b", "Phishing / scam heuristics: "), sev(ph.level === "minimal" ? "none" : ph.level)), h("div.small.muted", ph.signals.length ? ph.signals.slice(0, 2).map((s) => s.title).join(" · ") : "No warning signs found."))
    ) : null,
    h("div.chips",
      chip(" indicators", r.indicators.length, "indicators"),
      r.exposures.length ? chip(` exposures${sevCounts.critical ? ` (${sevCounts.critical} critical)` : sevCounts.high ? ` (${sevCounts.high} high)` : ""}`, r.exposures.length, "exposures", sevCounts.critical || sevCounts.high ? "active" : "") : null,
      chip(" trackers & IDs", r.trackers.length, "tech"),
      chip(" technologies", r.tech.length, "tech"),
      chip(" third parties", r.thirdParties.filter((t) => t.loaded).length, "links"),
      r.headers ? h("button.chip", { type: "button", onclick: () => ctx.setTab("infra") }, "Headers ", h(`span.grade.grade-${r.headers.grade}`, r.headers.grade)) : null,
      r.correlations?.length ? h("button.chip.active", { type: "button", onclick: () => ctx.setTab("overview") }, h("b", String(r.correlations.length)), " links to past scans") : null
    ),
    h("div.actions", onlineBtn, aiBtn, evBtn, exportBtn),
    job.online?.status === "error" ? h("div.small.check-fail", `Online lookups failed: ${job.online.error}`) : null,
    job.evidence?.status === "error" ? h("div.small.check-fail", `Evidence capture failed: ${job.evidence.error}`) : null,
    h("div.tiny.faint", `Scanned ${ago(r.createdAt)} · ${r.scanMs ? `${(r.scanMs / 1000).toFixed(1)} s` : ""}${r.online ? ` · online lookups ${ago(r.online.ranAt)}` : ""}`)
  );
}

async function capture(kind) {
  try {
    const res = await send("evidence", { reportId: S.report.id, tabId: S.tabId, kind });
    toast(`Saved. SHA-256 ${res.sha256.slice(0, 16)}…`);
  } catch (e) {
    toast(e.message, "error");
  }
}

async function startScan() {
  if (S.tabId == null) return;
  S.pinnedReportId = null;
  S.view = "report";
  await ctx.clearHighlights();
  try {
    await send("scan", { tabId: S.tabId });
  } catch (e) {
    toast(e.message, "error");
  }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === "local" && changes.settings) {
    S.settings = await getSettings();
    applyTheme();
    return;
  }
  if (area !== "session") return;
  if (changes.approvals) {
    S.approvals = changes.approvals.newValue || {};
    renderLive();
  }
  if (changes[`query:${S.windowId}`]?.newValue) {
    S.ui.lookupQuery = changes[`query:${S.windowId}`].newValue;
    S.view = "lookup";
    renderAll();
  }
  const tk = `tab:${S.tabId}`;
  if (changes[tk]) {
    const prev = S.tabState;
    S.tabState = changes[tk].newValue || null;
    if (!S.pinnedReportId && S.tabState?.reportId && S.tabState.reportId !== prev?.reportId) {
      S.tab = "overview";
      S.view = "report";
      await loadReport(S.tabState.reportId);
    } else renderAll();
  }
  const jk = S.report && `job:${S.report.id}`;
  if (jk && changes[jk]) {
    const prev = S.job || {};
    S.job = changes[jk].newValue || {};
    if (S.job.rev?.n !== prev.rev?.n) {
      // The stored report changed: reload it and re-render the current tab.
      S.report = await getReport(S.report.id);
      renderTabbar();
      renderContent();
      renderLive();
    } else {
      renderLive();
      // Refresh the summary's buttons without losing the tab's scroll/inputs.
      const card = document.querySelector(".summary");
      if (card) card.replaceWith(summaryCard());
      const doneNow = Object.keys(S.job).some((k) => S.job[k]?.status && S.job[k].status !== prev[k]?.status && S.job[k].status !== "running");
      if (doneNow) renderContent();
    }
  }
});

chrome.tabs.onActivated.addListener((info) => {
  if (!BOUND_TAB && info.windowId === S.windowId) refreshTab();
});
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (tabId === S.tabId && (info.status === "complete" || info.url)) refreshTab();
});

$("scan-btn").addEventListener("click", startScan);
$("history-btn").addEventListener("click", () => {
  S.view = S.view === "history" ? "report" : "history";
  renderAll();
});
$("lookup-btn").addEventListener("click", () => {
  S.view = S.view === "lookup" ? "report" : "lookup";
  renderAll();
});
$("settings-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("popout-btn").addEventListener("click", () => {
  if (S.tabId != null) chrome.tabs.create({ url: `${chrome.runtime.getURL("src/ui/sidepanel.html")}?tabId=${S.tabId}` });
});
if (BOUND_TAB) {
  $("popout-btn").classList.add("hidden");
  document.body.classList.add("popout");
}

function applyTheme() {
  const t = S.settings?.ui?.theme;
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}

(async function init() {
  S.settings = await getSettings();
  applyTheme();
  const win = await chrome.windows.getCurrent();
  S.windowId = win.id;
  S.approvals = (await chrome.storage.session.get("approvals")).approvals || {};
  const q = (await chrome.storage.session.get(`query:${S.windowId}`))[`query:${S.windowId}`];
  if (q && Date.now() - q.at < 15000) {
    S.ui.lookupQuery = q;
    S.view = "lookup";
  }
  await refreshTab();
})();

export { ctx, S };
