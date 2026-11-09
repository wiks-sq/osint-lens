// Lookup: investigate any value (typed, pasted, or right-clicked on a page):
// recognise what it is, show pivots, and search earlier investigations.

import { h, empty, toast, ext, copyBtn, badge, ago } from "./dom.js";
import { IndicatorBag, INDICATOR_TYPES } from "../core/indicators.js";
import { extractFromText, addUrl, addHost } from "../core/entities.js";
import { findTrackersInText } from "../core/trackers.js";
import { scanExposures } from "../core/exposures.js";
import { pivotsFor } from "../core/pivots.js";
import { isIP, registrableDomain } from "../core/domain.js";
import { md5 } from "../core/favicon.js";
import { searchIndicators } from "../shared/db.js";

/** Classify free text into indicators. */
export function classify(text) {
  const bag = new IndicatorBag();
  const t = String(text || "").trim();
  if (!t) return [];
  if (/^https?:\/\//i.test(t)) {
    const u = addUrl(bag, t, { source: "input" });
    if (u) {
      bag.add("domain", registrableDomain(u.hostname), { source: "input" });
      if (u.hostname !== registrableDomain(u.hostname)) addHost(bag, u.hostname, "input");
    }
  } else if (isIP(t)) addHost(bag, t, "input");
  else if (/^AS\d{1,10}$/i.test(t)) bag.add("asn", t.toUpperCase(), { source: "input" });
  else if (/^@?[A-Za-z0-9_.]{2,30}$/.test(t) && !/\./.test(t.replace(/^@/, ""))) bag.add("handle", t.startsWith("@") ? t : `@${t}`, { source: "input" });
  else if (/^-?\d{6,11}$/.test(t)) bag.add("favicon", t, { source: "input", label: "Number (favicon hash?)", extra: { mmh3: t }, confidence: "low" });
  extractFromText(bag, t, { source: "input" });
  for (const hit of findTrackersInText(` "${t}" `, "input")) bag.add("tracker", hit.value, { source: "input", label: hit.vendor, extra: { rule: hit.rule } });
  if (/^[a-z0-9\-]+(\.[a-z0-9\-]+)+$/i.test(t) && !isIP(t)) {
    bag.add("domain", registrableDomain(t), { source: "input" });
    if (registrableDomain(t) !== t.toLowerCase()) addHost(bag, t, "input");
  }
  const list = bag.list().filter((i) => i.type !== "url" || bag.list().length === 1);
  for (const i of list) if (i.type === "email") i.extra.md5 = md5(new TextEncoder().encode(i.value.trim().toLowerCase()));
  if (!list.length) list.push({ type: "organization", value: t.slice(0, 200), label: "Free text", sources: ["input"], extra: {}, count: 1 });
  return list;
}

export function render(ctx) {
  const ui = ctx.S.ui;
  const q = ui.lookupQuery;
  ui.lookupQuery = null;
  if (q?.text) ui.lookupText = q.text;
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const input = h("textarea", { rows: 2, placeholder: "Paste anything: a domain, URL, IP, email, phone, wallet, username, GA/AdSense ID, favicon hash…", value: ui.lookupText || "" });
  const results = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const go = () => {
    ui.lookupText = input.value;
    draw();
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      go();
    }
  });
  out.append(h("div.card", { style: { display: "flex", flexDirection: "column", gap: "8px" } },
    h("h2", { style: { fontSize: "14px" } }, "Investigate a value"),
    input,
    h("div.row", h("button.btn.primary.small", { type: "button", onclick: go }, "Investigate"), h("span.tiny.faint", "Tip: select text on any page, right-click → Investigate"))
  ), results);

  const draw = async () => {
    results.replaceChildren();
    const text = (ui.lookupText || "").trim();
    if (!text) return;
    const secrets = scanExposures(text);
    if (secrets.some((s) => ["critical", "high"].includes(s.severity))) results.append(h("div.notice.warn", h("div", h("b", "This looks like a secret or personal data "), `(${secrets[0].label}). Be careful: pivot links send the value to third-party sites.`)));
    const inds = classify(text).slice(0, 30);
    for (const i of inds) {
      const pivots = pivotsFor(i);
      const hits = await searchIndicators(String(i.value).toLowerCase(), 50).catch(() => []);
      const exact = hits.filter((x) => x.ind === `${i.type}|${String(i.value).trim().toLowerCase()}`);
      const mcpBtn = ctx.S.settings.mcp.servers.some((s) => s.enabled) && ctx.S.report
        ? h("button.btn.tiny", { type: "button", onclick: () => ctx.openMcp(i) }, "Send to MCP tool")
        : null;
      results.append(h("div.card", { style: { display: "flex", flexDirection: "column", gap: "6px" } },
        h("div.row.wrap-row", badge(INDICATOR_TYPES[i.type] || i.type, "accent"), i.label ? h("span.meta", i.label) : null, h("div.spacer"), copyBtn(i.value), mcpBtn),
        h("div.value.wrap", { style: { fontFamily: "var(--mono)" } }, i.value),
        pivots.length ? h("div.row.wrap-row", pivots.map((p) => ext(p.url, p.name, "small"))) : h("div.small.faint", "No pivot services for this type."),
        exact.length ? h("div.small", h("b", "In your history: "), exact.slice(0, 10).map((x, n) => [n ? ", " : "", h("a", { href: "#", onclick: (e) => (e.preventDefault(), ctx.openReport(x.reportId)) }, `${x.site} (${ago(x.createdAt)})`)])) : null
      ));
    }
    if (!inds.length) results.append(empty("Couldn't recognise that."));
    if (q?.kind === "investigate-link" && /^https?:/.test(text)) results.append(h("div.small.muted", "To scan the linked page itself, open it and press Scan."));
  };
  draw().catch((e) => toast(e.message, "error"));
  return out;
}
