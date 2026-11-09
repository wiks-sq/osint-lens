// AI analysis: choose a mode, watch tool calls live, read the structured
// result and ask follow-up questions.

import { h, section, empty, sev, badge, send, toast, ago, copyBtn } from "../dom.js";
import { renderMarkdown } from "../markdown.js";
import { MODES } from "../../ai/prompts.js";
import { isLocalEndpoint } from "../../ai/providers.js";

const STATUS_ICON = { pending: "…", running: "⟳", done: "✓", error: "✗", declined: "⊘", skipped: "–" };

function providerInfo(settings) {
  const a = settings.ai;
  if (a.provider === "openai") return { name: "OpenAI-compatible", model: a.openai.model, local: isLocalEndpoint(a.openai.url), endpoint: a.openai.url };
  if (a.provider === "anthropic") return { name: "Anthropic", model: a.anthropic.model, local: false, endpoint: "api.anthropic.com" };
  return { name: "Ollama", model: a.ollama.model, local: isLocalEndpoint(a.ollama.url), endpoint: a.ollama.url };
}

export function live(ctx) {
  const j = ctx.S.job.ai;
  const box = h("div", { dataset: { live: "ai" }, style: { display: "flex", flexDirection: "column", gap: "8px" } });
  if (!j?.status) return box;
  if (j.status === "running") {
    box.append(h("div.notice", h("div.spin"), h("div.grow", j.followUp ? "Answering…" : "Analysing…", h("div.small.muted", "You can close the panel; the analysis keeps running.")), h("button.btn.small", { type: "button", onclick: () => send("cancel", { reportId: ctx.S.report.id, slot: "ai" }) }, "Cancel")));
  } else if (j.status === "error") box.append(h("div.notice.error", h("div", h("b", "AI analysis failed: "), j.error)));
  else if (j.status === "cancelled") box.append(h("div.notice.warn", "Cancelled."));
  const events = (j.events || []).filter((e) => e.type !== "status" || j.status === "running");
  if (events.length && j.status === "running") {
    box.append(h("div.card.events", events.map((e) => {
      if (e.type === "tool") {
        const en = e.entry;
        return h("div.event", h("span", { title: en.status, style: { width: "14px", fontWeight: 700 } }, STATUS_ICON[en.status] || "·"), h("div.grow", h("div", h("b", en.tool), " ", badge(en.source)), h("div.args", JSON.stringify(en.args).slice(0, 300)), en.result && en.status !== "running" ? h("div.args", { style: { opacity: 0.8 } }, en.result.slice(0, 200)) : null));
      }
      if (e.type === "thinking") return h("details", h("summary.small.muted", "Model reasoning"), h("div.thinking", e.text));
      return h("div.event.muted", h("span", "·"), h("div", e.text));
    })));
  }
  return box;
}

export function render(ctx) {
  const { S } = ctx;
  const r = S.report;
  const ui = (S.ui.ai ||= { mode: "osint", question: "" });
  if (S.ui.aiQuestion) {
    ui.mode = r.ai?.result ? ui.mode : "custom";
    ui.question = S.ui.aiQuestion;
    ui.followUp = S.ui.aiQuestion;
    S.ui.aiQuestion = null;
  }
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const p = providerInfo(S.settings);
  const running = S.job.ai?.status === "running";
  const mcpServers = S.settings.mcp.servers.filter((s) => s.enabled && s.useInAi);

  // --- Setup --------------------------------------------------------------------
  const modeSel = h("select", { onchange: (e) => ((ui.mode = e.target.value), ctx.rerender()) },
    Object.entries(MODES).map(([id, m]) => h("option", { value: id, selected: ui.mode === id }, m.label)),
    h("option", { value: "custom", selected: ui.mode === "custom" }, "Ask a custom question")
  );
  const q = h("textarea", { rows: 3, placeholder: "What do you want to know about this page?", value: ui.question, oninput: (e) => (ui.question = e.target.value) });
  const run = h("button.btn.primary", { type: "button", disabled: running || !p.model }, r.ai?.result ? "Run again" : "Analyse");
  run.addEventListener("click", () => {
    if (ui.mode === "custom" && !ui.question.trim()) return toast("Type a question first.");
    send("ai", { reportId: r.id, mode: ui.mode, question: ui.mode === "custom" ? ui.question.trim() : undefined }).catch((e) => toast(e.message, "error"));
  });
  out.append(h("div.card", { style: { display: "flex", flexDirection: "column", gap: "8px" } },
    h("div.row.wrap-row",
      h("b", p.name), p.model ? h("span.mono", p.model) : h("span.check-fail", "no model selected"),
      p.local ? badge("local", "good") : badge("remote: data leaves this computer", "warn"),
      h("div.spacer"),
      h("button.btn.tiny.ghost", { type: "button", onclick: () => chrome.runtime.openOptionsPage() }, "Settings")
    ),
    !p.model ? h("div.notice.warn", "Choose a provider and model in Settings → AI.") : null,
    h("div.row", modeSel, run),
    ui.mode === "custom" ? q : h("div.small.muted", modeHint(ui.mode)),
    h("div.tiny.faint", S.settings.ai.useTools
      ? `Tools: built-in lookups${mcpServers.length ? ` + MCP: ${mcpServers.map((s) => s.name).join(", ")}` : " (add MCP servers in Settings to give the AI more tools)"}. Up to ${S.settings.ai.maxToolCalls} calls; MCP calls need your approval unless you allowed them.`
      : "Tools are off: the model only sees the scan digest.",
      p.local ? "" : " Secrets in the digest are masked for remote providers.")
  ));
  out.append(live(ctx));

  // --- Result -----------------------------------------------------------------------
  const a = r.ai;
  if (a?.result) out.append(resultView(ctx, a));
  else if (a?.raw) out.append(section("Model answer (not in the expected format)", renderMarkdown(a.raw)));
  else if (!running) out.append(h("div.card", empty("No analysis yet. The model gets a digest of everything the scan found (plus online lookups, file metadata and MCP results if you ran them) and the page text.")));

  // --- Follow-ups ------------------------------------------------------------------------
  if (a?.result || a?.raw) {
    const fq = h("textarea", { rows: 2, placeholder: "Ask a follow-up question…", value: ui.followUp || "" });
    const ask = h("button.btn.small.primary", { type: "button", disabled: running }, "Ask");
    ask.addEventListener("click", () => {
      const question = fq.value.trim();
      if (!question) return;
      ui.followUp = "";
      send("followUp", { reportId: r.id, question }).catch((e) => toast(e.message, "error"));
    });
    fq.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) ask.click();
    });
    out.append(section("Follow-up questions", [
      ...(a.followUps || []).map((f) => h("div.item", h("div.main", h("div", h("b", "Q: "), f.question), h("div", { style: { marginTop: "4px" } }, renderMarkdown(f.answer)), f.log?.length ? h("div.tiny.faint", `${f.log.length} tool call(s)`) : null))),
      fq,
      h("div.row", ask, h("span.tiny.faint", "Ctrl+Enter to send"))
    ], { count: a.followUps?.length || null }));
  }
  return out;
}

function modeHint(mode) {
  return {
    osint: "Who runs the site, how it connects to other sites, people and organisations, what's exposed, and the best next pivots.",
    phishing: "Phishing, scam, fake shop, crypto drainer or legitimate? Decisive evidence and next steps.",
    exposure: "Personal data, credentials, confidential material and leaky metadata on this page, with fixes."
  }[mode] || "";
}

function resultView(ctx, a) {
  const res = a.result;
  const wrap = h("div.card.ai-result", { style: { display: "flex", flexDirection: "column", gap: "8px" } });
  wrap.append(
    h("div.row.wrap-row", sev(res.risk_level), h("span.verdict", res.verdict || "Analysis"), h("div.spacer"), copyBtn(() => JSON.stringify(res, null, 2), "Copy JSON")),
    res.summary ? h("p", res.summary) : null,
    res.attribution ? h("p", h("b", "Attribution: "), res.attribution) : null,
    h("div.tiny.faint", `${MODES[a.mode]?.label || a.mode}${a.question ? ` · "${a.question.slice(0, 80)}"` : ""} · ${a.model} · ${ago(a.at)}${a.log?.length ? ` · ${a.log.length} tool call(s)` : ""}`)
  );
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } }, wrap);
  if (res.key_findings?.length) out.append(section("Key findings", h("div.list", res.key_findings.map((f) => h("div.item", sev(f.severity), h("div.main", h("b", f.title), f.detail ? h("div.small", f.detail) : null, f.evidence ? h("div.ctx.mono", f.evidence) : null)))), { count: res.key_findings.length }));
  if (res.exposures?.length) out.append(section("Exposures (AI)", h("div.list", res.exposures.map((e) => h("div.item", sev(e.severity), h("div.main", h("b", e.category), h("div.value", e.value), e.recommendation ? h("div.meta", e.recommendation) : null)))), { count: res.exposures.length }));
  if (res.entities?.length) out.append(section("Entities", h("div.list", res.entities.map((e) => {
    const pv = h("button.btn.tiny", { type: "button" }, "Pivot ▾");
    const map = { person: "person", organization: "organization", email: "email", phone: "phone", wallet: "crypto", domain: "domain", ip: "ip", account: "handle" };
    pv.addEventListener("click", () => ctx.pivotMenu(pv, { type: map[e.type] || "organization", value: e.value }));
    return h("div.item", badge(e.type), h("div.main", h("span.value", e.value), e.note ? h("div.meta", e.note) : null), h("div.tools", pv));
  })), { count: res.entities.length }));
  if (res.pivots?.length) out.append(section("Suggested next steps", h("div.list", res.pivots.map((p) => h("div.item", h("div.main", h("span.value", p.indicator), h("div.small", p.why), p.how ? h("div.meta", p.how) : null)))), { count: res.pivots.length }));
  if (a.log?.length) out.append(section("Tool calls", h("div.list", a.log.map((en) => h("div.item", h("span", { style: { width: "14px" } }, STATUS_ICON[en.status] || "·"), h("div.main", h("div", h("b", en.tool), " ", badge(en.source), " ", h("span.meta", en.status)), h("div.ctx.mono", JSON.stringify(en.args)), en.result ? h("details", h("summary.tiny.muted", "result"), h("pre.result-pre", en.result)) : null)))), { open: false, count: a.log.length }));
  return out;
}
