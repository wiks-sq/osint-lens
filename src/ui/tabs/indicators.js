// Indicators: every pivotable identifier, filterable by type, with pivot menus.

import { h, empty, limited, copyBtn, badge } from "../dom.js";
import { INDICATOR_TYPES } from "../../core/indicators.js";

const LOCATABLE = new Set(["email", "phone", "crypto", "onion", "iban", "business_id", "handle", "ip", "coordinates", "cve", "hash", "person", "organization", "address"]);

export function row(ctx, i) {
  const pivot = h("button.btn.tiny", { type: "button", title: "Pivot to other services" }, "Pivot ▾");
  pivot.addEventListener("click", (e) => {
    e.stopPropagation();
    ctx.pivotMenu(pivot, i);
  });
  const id = `ind:${i.type}:${i.value}`;
  const fromPage = i.sources.some((s) => /page text|page source|link|mailto|tel link/.test(s));
  const locate = LOCATABLE.has(i.type) && fromPage && ctx.isCurrentTab()
    ? h("button.btn.tiny.ghost", { type: "button", title: "Show on the page", onclick: () => ctx.highlight(id, { value: i.type === "phone" ? i.value : i.value, matchHref: true }, { focus: true }) }, "⌖")
    : null;
  const conf = i.confidence === "low" ? badge("low confidence") : i.confidence === "medium" ? badge("medium") : null;
  return h("div.item",
    h("div.main",
      h("div.row.wrap-row", h("span.value", i.type === "social" ? i.extra?.handle ? `${i.extra.handle}` : i.value : i.value), i.label ? h("span.meta", i.label) : null, conf, i.extra?.private ? badge("private") : null, i.extra?.placeholder ? badge("placeholder") : null),
      i.type === "social" ? h("div.meta.wrap", i.value) : null,
      h("div.meta", `${i.sources.slice(0, 3).join(", ")}${i.sources.length > 3 ? ` +${i.sources.length - 3}` : ""}${i.count > 1 ? ` · ${i.count}×` : ""}`),
      i.contexts?.[0] && i.contexts[0] !== i.value ? h("div.ctx", i.contexts[0]) : null,
      i.extra?.note ? h("div.ctx", `AI: ${i.extra.note}`) : null
    ),
    h("div.tools", locate, copyBtn(i.value), pivot)
  );
}

export function render(ctx) {
  const r = ctx.S.report;
  const ui = (ctx.S.ui.indicators ||= { type: null, q: "", hideLow: false });
  const out = h("div.card", { style: { display: "flex", flexDirection: "column", gap: "8px" } });
  const counts = {};
  for (const i of r.indicators) counts[i.type] = (counts[i.type] || 0) + 1;
  const search = h("input", { type: "search", placeholder: "Filter indicators…", value: ui.q });
  const listBox = h("div");
  const chips = h("div.filters",
    h("button.chip", { type: "button", class: !ui.type ? "active" : "", onclick: () => ((ui.type = null), ctx.rerender()) }, h("b", String(r.indicators.length)), " all"),
    Object.keys(INDICATOR_TYPES).filter((t) => counts[t]).map((t) => h("button.chip", { type: "button", class: ui.type === t ? "active" : "", onclick: () => ((ui.type = ui.type === t ? null : t), ctx.rerender()) }, h("b", String(counts[t])), ` ${INDICATOR_TYPES[t]}`))
  );
  const hideLow = h("label.check.small", h("input", { type: "checkbox", checked: ui.hideLow, onchange: (e) => ((ui.hideLow = e.target.checked), draw()) }), h("span", "Hide low-confidence"));

  const draw = () => {
    const q = ui.q.trim().toLowerCase();
    let items = r.indicators.filter((i) => (!ui.type || i.type === ui.type) && (!q || `${i.value} ${i.label || ""} ${i.sources.join(" ")}`.toLowerCase().includes(q)));
    if (ui.hideLow) items = items.filter((i) => i.confidence !== "low");
    listBox.replaceChildren(items.length ? groupList(ctx, items, !ui.type) : empty("No indicators match."));
  };
  search.addEventListener("input", () => {
    ui.q = search.value;
    draw();
  });
  out.append(search, chips, hideLow, listBox);
  draw();
  return out;
}

function groupList(ctx, items, grouped) {
  if (!grouped) return limited(items, (i) => row(ctx, i), 150);
  const wrap = h("div");
  const byType = new Map();
  for (const i of items) {
    if (!byType.has(i.type)) byType.set(i.type, []);
    byType.get(i.type).push(i);
  }
  for (const [t, list] of byType) {
    wrap.append(h("div.group-label", `${INDICATOR_TYPES[t] || t} (${list.length})`), limited(list, (i) => row(ctx, i), 25));
  }
  return wrap;
}
