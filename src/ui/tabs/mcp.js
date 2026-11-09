// MCP: run any tool from your connected MCP servers on this page's data,
// manage recipes, and see earlier results.

import { h, section, empty, badge, send, toast, ago, copyBtn, ext } from "../dom.js";
import { INDICATOR_TYPES } from "../../core/indicators.js";
import { fillTemplate } from "../../mcp/registry.js";
import { getSettings, saveSettings, newId } from "../../shared/settings.js";

export function live(ctx) {
  const j = ctx.S.job.mcp;
  if (j?.status === "running") return h("div.notice", { dataset: { live: "mcp" } }, h("div.spin"), h("div.grow", `Running ${j.tool}…`));
  if (j?.status === "error") return h("div.notice.error", { dataset: { live: "mcp" } }, h("div", h("b", "Tool call failed: "), j.error));
  return h("div", { dataset: { live: "mcp" } });
}

async function cache(serverId) {
  const k = `mcpCache:${serverId}`;
  return (await chrome.storage.local.get(k))[k] || null;
}

export function render(ctx) {
  const { S } = ctx;
  const r = S.report;
  const ui = (S.ui.mcp ||= { serverId: null, tool: null, args: {} });
  const servers = S.settings.mcp.servers.filter((s) => s.enabled);
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });

  if (!servers.length) {
    out.append(h("div.card",
      h("p", h("b", "Connect MCP servers to use any tool on this page's data.")),
      h("p.small.muted", "Model Context Protocol servers give OSINT Lens extra capabilities: threat-intel lookups (VirusTotal, Shodan, AbuseIPDB…), search engines, your case-management system, a headless browser, a database. Remote servers connect over HTTP; local (stdio) servers through the bundled bridge."),
      h("button.btn.primary.small", { type: "button", onclick: () => chrome.runtime.openOptionsPage() }, "Add an MCP server")
    ));
    return out;
  }
  out.append(live(ctx));

  if (!ui.serverId || !servers.some((s) => s.id === ui.serverId)) ui.serverId = servers[0].id;
  const server = servers.find((s) => s.id === ui.serverId);
  const body = h("div", { style: { display: "flex", flexDirection: "column", gap: "8px" } }, h("div.status-line", h("div.spin"), "Loading tools…"));
  const serverSel = h("select", { onchange: (e) => ((ui.serverId = e.target.value), (ui.tool = null), ctx.rerender()) }, servers.map((s) => h("option", { value: s.id, selected: s.id === ui.serverId }, s.name)));
  const refresh = h("button.btn.small", { type: "button", title: "Reconnect and reload the tool list" }, "Refresh");
  refresh.addEventListener("click", async () => {
    refresh.disabled = true;
    await send("mcpInspect", { server }).catch((e) => toast(e.message, "error"));
    ctx.rerender();
  });
  out.append(h("div.card", { style: { display: "flex", flexDirection: "column", gap: "8px" } }, h("div.row", serverSel, refresh), body));

  (async () => {
    let c = await cache(server.id);
    if (!c || !c.ok) c = await send("mcpInspect", { server }).catch((e) => ({ ok: false, error: e.message }));
    body.replaceChildren();
    if (!c.ok) {
      body.append(h("div.notice.error", h("div", h("b", "Couldn't connect: "), c.error, h("div.small", "Check the server in Settings → MCP servers."))));
      return;
    }
    const tools = (c.tools || []).filter((t) => !(server.disabledTools || []).includes(t.name));
    body.append(h("div.tiny.faint", `${c.info?.serverInfo?.name || server.name}${c.info?.serverInfo?.version ? ` ${c.info.serverInfo.version}` : ""} · ${c.info?.transport} · protocol ${c.info?.protocolVersion} · ${tools.length} tools · checked ${ago(c.at)}`));
    if (c.info?.instructions) body.append(h("details", h("summary.small.muted", "Server instructions"), h("div.small", c.info.instructions.slice(0, 2000))));
    if (!tools.length) return body.append(empty("This server has no tools."));
    if (!ui.tool || !tools.some((t) => t.name === ui.tool)) ui.tool = tools[0].name;
    const toolSel = h("select", { onchange: (e) => ((ui.tool = e.target.value), (ui.args = {}), draw()) }, tools.map((t) => h("option", { value: t.name, selected: t.name === ui.tool }, t.title || t.annotations?.title || t.name)));
    const formBox = h("div");
    body.append(toolSel, formBox);
    const draw = () => formBox.replaceChildren(toolForm(ctx, server, tools.find((t) => t.name === ui.tool), ui));
    draw();
  })();

  // --- Recipes ------------------------------------------------------------------------
  const recipes = S.settings.recipes.filter((x) => servers.some((s) => s.id === x.serverId));
  out.append(section("Recipes", recipes.length ? h("div.list", recipes.map((rc) => h("div.item", h("div.main", h("b", rc.name), h("div.meta", `${servers.find((s) => s.id === rc.serverId)?.name} / ${rc.tool}${rc.auto ? " · runs after every scan" : ""}`), h("div.ctx.mono", rc.args)),
    h("div.tools", h("button.btn.tiny", { type: "button", onclick: () => send("recipe", { reportId: r.id, recipeId: rc.id }).catch((e) => toast(e.message, "error")) }, "Run"))))) : empty("Save a tool call as a recipe to re-run it on any page with one click. Recipes can use {url}, {host}, {domain}, {ip}, {email} and {title}."), { open: recipes.length > 0, count: recipes.length || null }));

  // --- Results ------------------------------------------------------------------------
  const results = [...(r.mcp || [])].reverse();
  out.append(section("Results for this page", results.length ? h("div.list", results.map((m) => h("div.item", h("div.main",
    h("div.row.wrap-row", h("b", `${m.server} / ${m.tool}`), m.isError ? badge("error", "bad") : null, badge(m.by === "ai" ? "by AI" : m.by), h("span.meta", ago(m.at))),
    h("div.ctx.mono", JSON.stringify(m.args)),
    h("pre.result-pre", m.text),
    (m.images || []).map((img) => h("img.thumb", { src: `data:${img.mimeType};base64,${img.data}`, alt: "Tool result image" })),
    h("div", copyBtn(m.text, "Copy result"))
  )))) : empty("No MCP results yet."), { count: results.length || null }));
  return out;
}

/** Build an input form from a tool's JSON Schema. */
function toolForm(ctx, server, tool, ui) {
  const r = ctx.S.report;
  const schema = tool.inputSchema || {};
  const props = schema.properties || {};
  const required = new Set(schema.required || []);
  const form = h("div.tool-form");
  if (tool.description) form.append(h("div.small.muted", tool.description.slice(0, 800)));
  const ro = tool.annotations?.readOnlyHint;
  form.append(h("div.row.wrap-row", ro ? badge("read-only", "good") : badge("may change data", "warn"), tool.annotations?.openWorldHint ? badge("uses external services") : null));

  // Prefill from an indicator handed over by a pivot menu.
  const pre = ctx.S.ui.mcpPrefill;
  if (pre) {
    ctx.S.ui.mcpPrefill = null;
    const target = Object.entries(props).find(([k, p]) => p.type === "string" && new RegExp(pre.type === "ip" ? "ip|address|host|target|query" : pre.type === "domain" || pre.type === "host" ? "domain|host|url|target|query|site" : pre.type === "email" ? "email|query|target" : "query|value|target|input|q|indicator|observable", "i").test(k)) || Object.entries(props).find(([, p]) => p.type === "string");
    if (target) ui.args[target[0]] = pre.value;
  }

  const inputs = {};
  const suggestions = [...new Set([r.page.url, r.page.host, r.page.site, ...r.indicators.filter((i) => ["ip", "email", "domain", "tracker", "crypto", "phone", "social", "host"].includes(i.type) && !i.extra?.private).slice(0, 60).map((i) => i.value)])];
  const listId = `mcp-sugg-${Math.random().toString(36).slice(2)}`;
  form.append(h("datalist", { id: listId }, suggestions.map((s) => h("option", { value: s }))));

  for (const [name, p] of Object.entries(props)) {
    const label = h("span", name, required.has(name) ? " *" : "", p.description ? h("span.hint", ` — ${p.description.slice(0, 200)}`) : null);
    let input;
    const cur = ui.args[name] ?? p.default;
    if (p.enum) input = h("select", h("option", { value: "" }, "—"), p.enum.map((v) => h("option", { value: String(v), selected: String(cur) === String(v) }, String(v))));
    else if (p.type === "boolean") input = h("input", { type: "checkbox", checked: !!cur });
    else if (p.type === "number" || p.type === "integer") input = h("input", { type: "number", value: cur ?? "", step: p.type === "integer" ? 1 : "any" });
    else if (p.type === "object" || p.type === "array") input = h("textarea", { rows: 3, placeholder: p.type === "array" ? '["…"]' : "{ … }", value: cur != null ? JSON.stringify(cur) : "" });
    else input = h("input", { type: "text", list: listId, value: cur ?? "", placeholder: "Type or pick a value from this page" });
    input.dataset.kind = p.enum ? "enum" : p.type || "string";
    inputs[name] = input;
    form.append(h("label.field", p.type === "boolean" ? h("span.row", input, label) : [label, input]));
  }
  if (!Object.keys(props).length) form.append(h("div.small.faint", "This tool takes no arguments."));

  const collect = () => {
    const args = {};
    for (const [name, input] of Object.entries(inputs)) {
      const kind = input.dataset.kind;
      if (kind === "boolean") args[name] = input.checked;
      else if (input.value === "") continue;
      else if (kind === "number" || kind === "integer") args[name] = Number(input.value);
      else if (kind === "object" || kind === "array") {
        try {
          args[name] = JSON.parse(input.value);
        } catch {
          throw new Error(`"${name}" must be valid JSON`);
        }
      } else if (kind === "enum") {
        const ev = props[name].enum.find((v) => String(v) === input.value);
        args[name] = ev ?? input.value;
      } else args[name] = input.value;
    }
    for (const req of required) if (args[req] === undefined) throw new Error(`"${req}" is required`);
    return args;
  };
  for (const input of Object.values(inputs)) input.addEventListener("input", () => {
    try {
      ui.args = collect();
    } catch {
      /* incomplete form */
    }
  });

  const run = h("button.btn.primary.small", { type: "button", disabled: ctx.S.job.mcp?.status === "running" }, "Run tool");
  run.addEventListener("click", async () => {
    let args;
    try {
      args = collect();
    } catch (e) {
      return toast(e.message, "error");
    }
    run.disabled = true;
    try {
      await send("mcpTool", { reportId: r.id, serverId: server.id, tool: tool.name, args });
    } catch (e) {
      toast(e.message, "error");
    } finally {
      run.disabled = false;
    }
  });
  const saveRecipe = h("button.btn.small", { type: "button", title: "Save these arguments as a reusable recipe; replace values with {domain}, {url}, {host}, {ip}, {email}" }, "Save as recipe");
  saveRecipe.addEventListener("click", async () => {
    let args;
    try {
      args = collect();
    } catch (e) {
      return toast(e.message, "error");
    }
    // Generalise values from this page into placeholders.
    const json = JSON.stringify(args).split(r.page.url).join("{url}").split(r.page.host).join("{host}").split(r.page.site).join("{domain}");
    const nameInput = h("input", { type: "text", value: `${tool.name} (${server.name})` });
    const ok = h("button.btn.small.primary", { type: "button" }, "Save");
    const row = h("div.row", nameInput, ok);
    saveRecipe.replaceWith(row);
    nameInput.focus();
    ok.addEventListener("click", async () => {
      const name = nameInput.value.trim();
      if (!name) return;
      try {
        fillTemplate(json, r);
      } catch (e) {
        return toast(e.message, "error");
      }
      const s = await getSettings();
      s.recipes.push({ id: newId(), name, serverId: server.id, tool: tool.name, args: json, auto: false });
      await saveSettings(s);
      toast("Recipe saved. Edit it in Settings.");
      row.replaceWith(saveRecipe);
    });
  });
  form.append(h("div.row", run, saveRecipe, h("div.spacer"), ext(chrome.runtime.getURL("src/ui/options.html#mcp"), "Manage servers", "small")));
  form.append(h("div.tiny.faint", `Suggestions come from this page's indicators (${INDICATOR_TYPES.ip}, ${INDICATOR_TYPES.email}, ${INDICATOR_TYPES.domain}…). Values you send go to the MCP server.`));
  return form;
}
