// Settings page.

import { h, clear, send, toast, download, badge, ago } from "./dom.js";
import { getSettings, saveSettings, DEFAULTS, deepMerge, newId } from "../shared/settings.js";
import { ONLINE_SOURCES } from "../intel/enrich.js";
import { isLocalEndpoint } from "../ai/providers.js";

let cfg;
let dirty = false;
const $ = (id) => document.getElementById(id);

const markDirty = () => {
  dirty = true;
  $("save-state").textContent = "Unsaved changes";
};

/** Bind an input to a path in cfg ("ai.ollama.url"). */
function bind(input, path, { type = "text", parse } = {}) {
  const keys = path.split(".");
  const get = () => keys.reduce((o, k) => o?.[k], cfg);
  const set = (v) => {
    const last = keys.pop();
    const obj = keys.reduce((o, k) => (o[k] ||= {}), cfg);
    keys.push(last);
    obj[last] = v;
    markDirty();
  };
  if (type === "checkbox") {
    input.checked = !!get();
    input.addEventListener("change", () => set(input.checked));
  } else {
    input.value = get() ?? "";
    input.addEventListener("input", () => set(parse ? parse(input.value) : input.value));
  }
  return input;
}

const field = (label, input, hint) => h("label.field", h("span", label, hint ? h("span.hint", ` ${hint}`) : null), input);
const check = (label, path, hint) => h("label.check", bind(h("input", { type: "checkbox" }), path, { type: "checkbox" }), h("span", label, hint ? h("div.hint.small.faint", hint) : null));
const num = (path, min, max, step = 1) => bind(h("input", { type: "number", min, max, step }), path, { parse: (v) => Math.min(max, Math.max(min, Number(v) || min)) });
const text = (path, placeholder = "", type = "text") => bind(h("input", { type, placeholder, autocomplete: "off", spellcheck: "false" }), path);

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function aiSection() {
  const a = cfg.ai;
  const body = h("div", { style: { display: "flex", flexDirection: "column", gap: "12px" } });
  const tabs = h("div.provider-tabs", [["ollama", "Ollama (local)"], ["openai", "OpenAI-compatible"], ["anthropic", "Anthropic"]].map(([id, label]) =>
    h(`button.btn.small${a.provider === id ? ".primary" : ""}`, { type: "button", onclick: () => ((a.provider = id), markDirty(), rerender()) }, label)));

  const modelBox = (path, provider, sub) => {
    const input = text(path, "model name");
    const listId = `models-${provider}`;
    input.setAttribute("list", listId);
    const dl = h("datalist", { id: listId });
    const status = h("span.small.muted");
    const load = h("button.btn.small", { type: "button" }, "Load models");
    load.addEventListener("click", async () => {
      status.textContent = "Loading…";
      try {
        if (!(await ensureOrigins([sub.url || ""].filter((u) => u && !isLocalEndpoint(u))))) return (status.textContent = "Permission needed to reach that server.");
        const { models, capabilities } = await send("aiModels", { provider, cfg: { ...sub } });
        dl.replaceChildren(...models.map((m) => h("option", { value: m.id }, m.params ? `${m.id} (${m.params})` : m.name || m.id)));
        status.textContent = `${models.length} model(s) available${capabilities ? `. ${sub.model}: ${capabilities.join(", ")}` : ""}`;
        if (!sub.model && models[0]) {
          sub.model = models[0].id;
          input.value = models[0].id;
          markDirty();
        }
        if (capabilities && !capabilities.includes("tools")) status.textContent += " — this model can't call tools; turn tools off or pick another model.";
      } catch (e) {
        status.textContent = e.message;
      }
    });
    return h("div", field("Model", h("div.row", input, load)), dl, status);
  };

  if (a.provider === "ollama") {
    body.append(
      h("div.grid2", field("Ollama address", text("ai.ollama.url", "http://localhost:11434", "url")), field("Context window (tokens)", num("ai.ollama.numCtx", 2048, 262144, 1024), "num_ctx; larger = more page text, more memory")),
      modelBox("ai.ollama.model", "ollama", a.ollama),
      check("Let thinking models reason before answering", "ai.ollama.think", "Slower, but small models call tools far more reliably with it. Only affects models with the thinking capability."),
      h("details", h("summary.small", "Getting a 403 error?"), h("div.small.muted",
        h("p", "Ollama only answers browsers from trusted origins. Recent versions trust extensions by default; for older ones set ", h("span.inline-code", 'OLLAMA_ORIGINS="chrome-extension://*"'), " and restart Ollama:"),
        h("pre.cmd", 'macOS:   launchctl setenv OLLAMA_ORIGINS "chrome-extension://*"  (then restart the app)\nLinux:   sudo systemctl edit ollama  →  [Service] Environment="OLLAMA_ORIGINS=chrome-extension://*"\nWindows: set a user environment variable OLLAMA_ORIGINS = chrome-extension://*  and restart Ollama\nManual:  OLLAMA_ORIGINS="chrome-extension://*" ollama serve')
      ))
    );
  } else if (a.provider === "openai") {
    body.append(
      h("p.small.muted", "Works with LM Studio, llama.cpp server, vLLM, LocalAI, Jan, OpenRouter, OpenAI and other servers that implement /v1/chat/completions."),
      h("div.grid2", field("Base URL", text("ai.openai.url", "http://localhost:1234/v1", "url"), "ends in /v1"), field("API key", text("ai.openai.apiKey", "optional for local servers", "password"))),
      modelBox("ai.openai.model", "openai", a.openai),
      !isLocalEndpoint(a.openai.url) ? h("div.notice.warn.small", "This endpoint isn't on your computer: page content will be sent to it. Secrets are masked in what's sent.") : null
    );
  } else {
    body.append(
      h("p.small.muted", "Uses the Anthropic Messages API directly from your browser with your own API key. Page content is sent to Anthropic; secrets are masked in what's sent."),
      h("div.grid2", field("API key", text("ai.anthropic.apiKey", "sk-ant-…", "password")), modelBox("ai.anthropic.model", "anthropic", a.anthropic))
    );
  }
  body.append(h("div.grid2",
    field("Max page characters sent", num("ai.maxChars", 2000, 400000, 1000), "≈ 4 characters per token"),
    field("Timeout per model call (s)", num("ai.timeoutSec", 20, 1800, 10)),
    field("Temperature", num("ai.temperature", 0, 1, 0.1)),
    field("Max tool calls per analysis", num("ai.maxToolCalls", 0, 50, 1))
  ));
  body.append(check("Let the AI use tools (built-in lookups and your MCP servers)", "ai.useTools", "The model decides which lookups to run. MCP tools ask for your approval unless you allow them."));
  body.append(check("Run an OSINT brief automatically after every scan", "ai.autoRun"));
  return card("ai", "AI analysis", "Keep Ollama for fully local analysis, or use any OpenAI-compatible server or Anthropic.", tabs, body);
}

function mcpSection() {
  const list = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  for (const s of cfg.mcp.servers) list.append(serverEditor(s));
  if (!cfg.mcp.servers.length) list.append(h("p.empty", "No MCP servers yet."));
  const addBlank = h("button.btn.small.primary", { type: "button", onclick: () => addServer({ name: "my-server", url: "https://" }) }, "Add server");
  const addBridge = h("button.btn.small", { type: "button", onclick: () => addServer({ name: "local", url: "http://127.0.0.1:8765/mcp", headers: [{ name: "Authorization", value: "Bearer " }] }) }, "Add local bridge");
  return card("mcp", "MCP servers", "Connect any Model Context Protocol server. Its tools become available in the MCP tab and, if you allow it, to the AI.",
    h("div.row.wrap-row", addBlank, addBridge),
    list,
    h("details", h("summary", h("b", "Using local (stdio) MCP servers")), h("div.small", { style: { display: "flex", flexDirection: "column", gap: "6px", marginTop: "6px" } },
      h("p", "Browsers can't start programs, so stdio servers (the ones you run with ", h("span.inline-code", "npx"), ", ", h("span.inline-code", "uvx"), " or ", h("span.inline-code", "docker"), ") need a small bridge that exposes them over HTTP. One is included in the repository (Node 18+, no dependencies):"),
      h("pre.cmd", "# one server\nnode tools/mcp-bridge.mjs -- npx -y @modelcontextprotocol/server-everything\n\n# several servers, Claude Desktop config format\nnode tools/mcp-bridge.mjs --config mcp-servers.json\n#   → http://127.0.0.1:8765/<name>/mcp"),
      h("p", "The bridge prints a bearer token: paste it into the server's Authorization header here (", h("span.inline-code", "Bearer <token>"), "). It only listens on localhost and rejects requests from web pages.")
    )),
    h("details", h("summary", h("b", "Transports and security")), h("div.small.muted", { style: { marginTop: "6px" } },
      h("p", "Auto-detect tries the 2026-07-28 stateless Streamable HTTP protocol, then the 2025 Streamable HTTP handshake with sessions, then the legacy HTTP+SSE transport (2024-11-05)."),
      h("p", "Tools from untrusted servers can be dangerous: an AI can be tricked by page content into calling them with bad arguments. Keep approval on \"Ask every time\" unless you trust both the server and its tools.")
    ))
  );
}

function addServer(base) {
  cfg.mcp.servers.push({ id: newId(), name: base.name, url: base.url, transport: "auto", headers: base.headers || [], enabled: true, useInAi: true, approval: "ask", disabledTools: [], allowedTools: [], timeoutSec: 120 });
  markDirty();
  rerender();
}

function serverEditor(s) {
  const box = h(`div.server${s.enabled ? "" : ".disabled"}`);
  const status = h("div.small");
  const tools = h("div");
  const nameIn = h("input", { type: "text", value: s.name, oninput: (e) => ((s.name = e.target.value.replace(/[^A-Za-z0-9_.\-]/g, "_")), markDirty()) });
  const urlIn = h("input", { type: "url", value: s.url, placeholder: "https://example.com/mcp", oninput: (e) => ((s.url = e.target.value.trim()), markDirty()) });
  const transport = h("select", { onchange: (e) => ((s.transport = e.target.value), markDirty()) }, [["auto", "Auto-detect"], ["streamable-2026", "Streamable HTTP (2026-07-28, stateless)"], ["streamable-2025", "Streamable HTTP (2025, sessions)"], ["sse-2024", "HTTP + SSE (legacy 2024-11-05)"]].map(([v, l]) => h("option", { value: v, selected: s.transport === v }, l)));
  const approval = h("select", { onchange: (e) => ((s.approval = e.target.value), markDirty()) }, [["ask", "Ask every time"], ["readonly", "Auto-approve tools marked read-only"], ["always", "Never ask (trusted server)"]].map(([v, l]) => h("option", { value: v, selected: s.approval === v }, l)));
  const headers = h("div", { style: { display: "flex", flexDirection: "column", gap: "4px" } });
  const drawHeaders = () => {
    headers.replaceChildren(...s.headers.map((hd, i) => h("div.headers-row",
      h("input", { type: "text", value: hd.name, placeholder: "Header", oninput: (e) => ((hd.name = e.target.value), markDirty()) }),
      h("input", { type: "password", value: hd.value, placeholder: "Value (e.g. Bearer …)", autocomplete: "off", oninput: (e) => ((hd.value = e.target.value), markDirty()) }),
      h("button.btn.small.ghost", { type: "button", onclick: () => (s.headers.splice(i, 1), markDirty(), drawHeaders()) }, "✕")
    )), h("div", h("button.btn.tiny", { type: "button", onclick: () => (s.headers.push({ name: "Authorization", value: "Bearer " }), markDirty(), drawHeaders()) }, "+ header")));
  };
  drawHeaders();

  const showTools = (entry) => {
    tools.replaceChildren();
    if (!entry) return;
    if (!entry.ok) return status.replaceChildren(h("span.check-fail", `✗ ${entry.error}`));
    const i = entry.info || {};
    status.replaceChildren(h("span.check-pass", "✓ Connected "), h("span.muted", `${i.serverInfo?.name || ""} ${i.serverInfo?.version || ""} · ${i.transport} · protocol ${i.protocolVersion} · ${entry.tools.length} tools${entry.resources?.length ? ` · ${entry.resources.length} resources` : ""} · ${ago(entry.at)}`), i.warning ? h("div.check-warn", i.warning) : null);
    if (!entry.tools.length) return;
    tools.append(h("div.small.muted", "Tools (untick to hide a tool from the AI and the MCP tab):"), h("div.tools-list", entry.tools.map((t) => h("label.check.small", { title: t.description || "" },
      h("input", { type: "checkbox", checked: !(s.disabledTools || []).includes(t.name), onchange: (e) => {
        s.disabledTools = (s.disabledTools || []).filter((x) => x !== t.name);
        if (!e.target.checked) s.disabledTools.push(t.name);
        markDirty();
      } }),
      h("span", t.name, t.annotations?.readOnlyHint ? h("span.badge.good", " ro") : null, (s.allowedTools || []).includes(t.name) ? h("span.badge.accent", " always allowed") : null)
    ))));
    if (s.allowedTools?.length) tools.append(h("button.btn.tiny", { type: "button", onclick: () => ((s.allowedTools = []), markDirty(), showTools(entry)) }, "Forget \"always allow\" choices"));
  };
  chrome.storage.local.get(`mcpCache:${s.id}`).then((o) => showTools(o[`mcpCache:${s.id}`]));

  const test = h("button.btn.small", { type: "button" }, "Test connection");
  test.addEventListener("click", async () => {
    const ok = await ensureOrigins([s.url].filter((u) => !isLocalEndpoint(u)));
    if (!ok) return status.replaceChildren(h("span.check-fail", "The extension needs permission to reach this server."));
    status.replaceChildren(h("span.spin"), " Connecting…");
    showTools(await send("mcpInspect", { server: JSON.parse(JSON.stringify(s)) }).catch((e) => ({ ok: false, error: e.message })));
  });
  const del = h("button.btn.small.danger", { type: "button" }, "Remove");
  del.addEventListener("click", () => {
    cfg.mcp.servers = cfg.mcp.servers.filter((x) => x.id !== s.id);
    cfg.recipes = cfg.recipes.filter((r) => r.serverId !== s.id);
    chrome.storage.local.remove(`mcpCache:${s.id}`);
    markDirty();
    rerender();
  });

  box.append(
    h("div.head", h("label.check", h("input", { type: "checkbox", checked: s.enabled, onchange: (e) => ((s.enabled = e.target.checked), markDirty(), box.classList.toggle("disabled", !s.enabled)) }), h("b", "Enabled")), h("div.spacer"), test, del),
    h("div.grid2", field("Name", nameIn, "letters, digits, - _ ."), field("URL", urlIn)),
    h("div.grid2", field("Transport", transport), field("Tool approval", approval)),
    field("Headers", headers, "for authentication, e.g. Authorization: Bearer <token>"),
    h("label.check", h("input", { type: "checkbox", checked: s.useInAi, onchange: (e) => ((s.useInAi = e.target.checked), markDirty()) }), h("span", "Offer this server's tools to the AI")),
    status,
    tools
  );
  return box;
}

function recipesSection() {
  const list = h("div", { style: { display: "flex", flexDirection: "column", gap: "8px" } });
  for (const r of cfg.recipes) {
    list.append(h("div.server",
      h("div.grid2",
        field("Name", h("input", { type: "text", value: r.name, oninput: (e) => ((r.name = e.target.value), markDirty()) })),
        field("Server", h("select", { onchange: (e) => ((r.serverId = e.target.value), markDirty()) }, cfg.mcp.servers.map((s) => h("option", { value: s.id, selected: s.id === r.serverId }, s.name))))
      ),
      field("Tool", h("input", { type: "text", value: r.tool, oninput: (e) => ((r.tool = e.target.value), markDirty()) })),
      field("Arguments (JSON)", h("textarea", { rows: 3, value: r.args, oninput: (e) => ((r.args = e.target.value), markDirty()) }), "placeholders: {url} {host} {domain} {ip} {email} {title}"),
      h("div.row", h("label.check", h("input", { type: "checkbox", checked: r.auto, onchange: (e) => ((r.auto = e.target.checked), markDirty()) }), h("span", "Run automatically after every scan")), h("div.spacer"),
        h("button.btn.small.danger", { type: "button", onclick: () => ((cfg.recipes = cfg.recipes.filter((x) => x !== r)), markDirty(), rerender()) }, "Remove"))
    ));
  }
  if (!cfg.recipes.length) list.append(h("p.empty", "No recipes. Create one from the MCP tab (\"Save as recipe\") or here."));
  const add = h("button.btn.small", { type: "button", disabled: !cfg.mcp.servers.length, onclick: () => (cfg.recipes.push({ id: newId(), name: "New recipe", serverId: cfg.mcp.servers[0]?.id, tool: "", args: '{ "domain": "{domain}" }', auto: false }), markDirty(), rerender()) }, "Add recipe");
  return card("recipes", "Recipes", "A recipe is a saved MCP tool call with placeholders, run on any page with one click or automatically after each scan.", list, h("div", add));
}

function scanSection() {
  return card("scan", "Scanning", "What a scan reads. Everything here stays on your computer.",
    check("Read the site's public files", "scan.wellKnown", "robots.txt, sitemap.xml, security.txt, humans.txt, ads.txt, app-ads.txt and the web app manifest. These are requested from the site like a normal visitor would."),
    check("Download the site's scripts to analyse them", "scan.externalScripts", "Finds tracker IDs, API endpoints, buckets, internal hosts and secrets in JavaScript files."),
    h("div.grid2", field("Max script files per scan", num("scan.maxScripts", 0, 200, 5))),
    check("Detect JavaScript libraries and runtime IDs", "scan.mainWorldProbe", "Reads framework versions and tag-manager IDs from the page's JavaScript (runs a tiny read-only probe in the page)."),
    check("Fingerprint the favicon", "scan.favicon"),
    check("Scan values typed into form fields", "scan.includeFormValues", "Password fields are never read, only whether they're filled in."),
    check("Run online lookups automatically after every scan", "scan.autoOnline", "Otherwise they run when you press \"Online lookups\".")
  );
}

function onlineSection() {
  return card("online", "Online lookups", "Public sources queried about the domain and its IPs. The target site isn't contacted; the services you enable see what you look up.",
    ONLINE_SOURCES.map((s) => check(s.label, `online.${s.key}`)),
    h("div.grid2", field("urlscan.io API key", text("online.urlscanKey", "optional (higher rate limits)", "password")))
  );
}

function privacySection() {
  const access = h("div.row.wrap-row");
  const drawAccess = async () => {
    const all = await chrome.permissions.contains({ origins: ["http://*/*", "https://*/*"] });
    access.replaceChildren(
      all ? badge("Access to all sites granted", "good") : badge("Per-site access", "warn"),
      all
        ? h("button.btn.small", { type: "button", onclick: async () => (await chrome.permissions.remove({ origins: ["http://*/*", "https://*/*"] }), drawAccess()) }, "Revoke")
        : h("button.btn.small", { type: "button", onclick: async () => (await chrome.permissions.request({ origins: ["http://*/*", "https://*/*"] }), drawAccess()) }, "Allow on all sites")
    );
  };
  drawAccess();
  const exportBtn = h("button.btn.small", { type: "button" }, "Export settings");
  const withSecrets = h("input", { type: "checkbox" });
  exportBtn.addEventListener("click", () => {
    const copy = structuredClone(cfg);
    if (!withSecrets.checked) {
      copy.ai.openai.apiKey = "";
      copy.ai.anthropic.apiKey = "";
      copy.online.urlscanKey = "";
      for (const s of copy.mcp.servers) for (const hd of s.headers) hd.value = "";
    }
    download("osint-lens-settings.json", JSON.stringify(copy, null, 2), "application/json");
  });
  const importIn = h("input", { type: "file", accept: "application/json,.json", style: { display: "none" } });
  importIn.addEventListener("change", async () => {
    try {
      const data = JSON.parse(await importIn.files[0].text());
      cfg = deepMerge(DEFAULTS, data);
      markDirty();
      rerender();
      toast("Imported. Review and press Save.");
    } catch (e) {
      toast(`Couldn't import: ${e.message}`, "error");
    }
  });
  const clearBtn = h("button.btn.small.danger", { type: "button" }, "Delete all scan history");
  clearBtn.addEventListener("click", async () => {
    if (clearBtn.dataset.c !== "1") return ((clearBtn.dataset.c = "1"), (clearBtn.textContent = "Click again to confirm"));
    await send("clearHistory");
    clearBtn.textContent = "Deleted";
  });
  return card("privacy", "Privacy & data", null,
    check("Keep a history of scans", "privacy.keepHistory", "Needed for cross-investigation correlation. When off, a report is deleted when its tab closes (unless you starred it)."),
    h("div.grid2", field("Reports to keep", num("privacy.historyLimit", 10, 10000, 10)), field("Theme", (() => {
      const sel = h("select", [["system", "System"], ["light", "Light"], ["dark", "Dark"]].map(([v, l]) => h("option", { value: v }, l)));
      return bind(sel, "ui.theme");
    })())),
    h("div", h("b.small", "Site access"), h("p.small.muted", "Without it the extension can only read a tab after you click its toolbar icon. With it, the side panel can scan any tab and download files from other sites for metadata analysis."), access),
    h("div.row.wrap-row", exportBtn, h("label.check.small", withSecrets, h("span", "include API keys and tokens")), h("button.btn.small", { type: "button", onclick: () => importIn.click() }, "Import settings"), importIn, h("div.spacer"), clearBtn)
  );
}

function aboutSection() {
  const v = chrome.runtime.getManifest().version;
  return card("about", "About", null,
    h("p.small", `OSINT Lens ${v}. Open source (MIT). `, h("a", { href: chrome.runtime.getURL("src/ui/welcome.html"), target: "_blank" }, "Getting started guide")),
    h("p.small.muted", "Use it on pages you're entitled to investigate and respect the terms of the services it queries. Heuristic findings are leads, not conclusions."),
    h("p.tiny.faint", "Find it useful? ", h("a", { href: "https://buymeacoffee.com/marginnotes", target: "_blank", rel: "noopener noreferrer" }, "Buy the author a coffee"), ".")
  );
}

function card(id, title, lead, ...children) {
  return h("section.card", { id }, h("h2", title), lead ? h("p.lead.small", lead) : null, children);
}

// ---------------------------------------------------------------------------

async function ensureOrigins(urls) {
  const origins = [];
  for (const u of urls) {
    try {
      const o = new URL(u);
      if (/^https?:$/.test(o.protocol)) origins.push(`${o.origin}/*`);
    } catch {
      /* ignore */
    }
  }
  if (!origins.length) return true;
  if (await chrome.permissions.contains({ origins })) return true;
  return chrome.permissions.request({ origins });
}

/** Origins of remote MCP servers and AI endpoints that need host permission. */
function neededOrigins() {
  const urls = cfg.mcp.servers.filter((s) => s.enabled).map((s) => s.url);
  if (cfg.ai.provider === "openai") urls.push(cfg.ai.openai.url);
  if (cfg.ai.provider === "ollama") urls.push(cfg.ai.ollama.url);
  const out = new Set();
  for (const u of urls) {
    try {
      const o = new URL(u);
      if (/^https?:$/.test(o.protocol) && !isLocalEndpoint(u)) out.add(`${o.origin}/*`);
    } catch {
      /* invalid URL: validation reports it */
    }
  }
  return [...out];
}

function validate() {
  const errors = [];
  const names = new Set();
  for (const s of cfg.mcp.servers) {
    try {
      const u = new URL(s.url);
      if (!/^https?:$/.test(u.protocol)) errors.push(`${s.name}: URL must start with http:// or https://`);
      if (u.protocol === "http:" && !isLocalEndpoint(s.url)) errors.push(`${s.name}: use https:// for servers that aren't on this computer`);
    } catch {
      errors.push(`${s.name}: invalid URL`);
    }
    if (!s.name) errors.push("Every MCP server needs a name");
    if (names.has(s.name)) errors.push(`Duplicate server name "${s.name}"`);
    names.add(s.name);
  }
  for (const r of cfg.recipes) {
    try {
      JSON.parse(r.args || "{}");
    } catch {
      errors.push(`Recipe "${r.name}": arguments aren't valid JSON`);
    }
  }
  return errors;
}

async function save() {
  // Ask for host permissions first, while we still have the click's user gesture.
  const origins = neededOrigins();
  const permPromise = origins.length ? chrome.permissions.request({ origins }).catch(() => false) : Promise.resolve(true);
  const errors = validate();
  if (errors.length) {
    await permPromise;
    return toast(errors[0], "error");
  }
  const granted = await permPromise;
  await saveSettings(cfg);
  dirty = false;
  $("save-state").textContent = granted ? "Saved" : "Saved (some servers need permission: press Save again to grant it)";
  setTimeout(() => !dirty && ($("save-state").textContent = ""), 2500);
}

function rerender() {
  const form = clear($("form"));
  const sections = [aiSection(), mcpSection(), recipesSection(), scanSection(), onlineSection(), privacySection(), aboutSection()];
  form.append(...sections);
  clear($("nav")).append(...sections.map((s) => h("a", { href: `#${s.id}` }, s.querySelector("h2").textContent)));
}

$("save").addEventListener("click", save);
window.addEventListener("beforeunload", (e) => {
  if (dirty) e.preventDefault();
});
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "s") {
    e.preventDefault();
    save();
  }
});

(async () => {
  cfg = await getSettings();
  const t = cfg.ui?.theme;
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  rerender();
  if (location.hash) document.querySelector(location.hash)?.scrollIntoView();
})();
