// Links, forms, frames and HTML comments.

import { h, section, empty, ext, limited, badge, kv } from "../dom.js";

export function render(ctx) {
  const r = ctx.S.report;
  const ui = (ctx.S.ui.links ||= { filter: "notable", q: "" });
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });

  // --- Forms -------------------------------------------------------------------
  out.append(section("Forms", r.forms.length ? h("div.list", r.forms.map((f) => h("div.item", { class: (f.hasPassword || f.hasCard) && (f.external || f.insecure) ? "flagged" : "" }, h("div.main",
    h("div.row.wrap-row",
      h("b", f.virtual ? "Inputs outside a form" : `${f.method.toUpperCase()} form`),
      f.hasPassword ? badge("password", "warn") : null,
      f.hasCard ? badge("card", "warn") : null,
      f.hasEmail ? badge("email / user") : null,
      f.external ? badge(`submits to ${f.actionHost}`, "bad") : null,
      f.insecure ? badge("plain HTTP", "bad") : null
    ),
    f.action ? h("div.meta.wrap", `→ ${f.action}`) : h("div.meta", "Handled by JavaScript"),
    h("div.chips", f.fields.slice(0, 30).map((x) => h("span.chip", { title: x.label || "" }, `${x.name || x.label || "?"}:${x.type}`))),
    f.hiddenFields?.length ? h("div.ctx", `Hidden fields: ${f.hiddenFields.map((x) => x.name).join(", ")}`) : null
  )))) : empty("No forms."), { count: r.forms.length }));

  // --- Links ----------------------------------------------------------------------
  const extCounts = {};
  for (const l of r.links) if (l.ext) extCounts[l.ext] = (extCounts[l.ext] || 0) + 1;
  const filters = [
    ["notable", "worth checking", (l) => l.notable],
    ["all", "all", () => true],
    ["external", "external", (l) => l.external],
    ["secrets", "secret in URL", (l) => l.secretParams.length],
    ["insecure", "plain HTTP", (l) => l.insecure],
    ["email", "mailto", (l) => l.category === "email"],
    ["phone", "tel", (l) => l.category === "phone"],
    ...Object.keys(extCounts).sort((a, b) => extCounts[b] - extCounts[a]).slice(0, 14).map((e) => [`ext:${e}`, `.${e}`, (l) => l.ext === e])
  ];
  const list = h("div");
  const search = h("input", { type: "search", placeholder: "Filter links…", value: ui.q });
  const chips = h("div.filters");
  const draw = () => {
    const f = filters.find(([id]) => id === ui.filter) || filters[0];
    const q = ui.q.trim().toLowerCase();
    const items = r.links.filter(f[2]).filter((l) => !q || `${l.url} ${l.text}`.toLowerCase().includes(q));
    chips.replaceChildren(...filters.map(([id, label, fn]) => {
      const n = r.links.filter(fn).length;
      if (!n && id !== "notable" && id !== "all") return "";
      return h("button.chip", { type: "button", class: ui.filter === id ? "active" : "", onclick: () => ((ui.filter = id), draw()) }, h("b", String(n)), ` ${label}`);
    }));
    list.replaceChildren(items.length ? limited(items, (l) => linkRow(ctx, l), 100) : empty(ui.filter === "notable" ? "No documents, data files, configs, archives or links with credentials." : "No links match."));
  };
  search.addEventListener("input", () => ((ui.q = search.value), draw()));
  draw();
  out.append(section("Links", [search, chips, list], { count: r.links.length }));

  // --- Frames ------------------------------------------------------------------------
  if (r.iframes.length) out.append(section("Embedded frames and objects", h("div.list", r.iframes.map((f) => h("div.item", h("div.main", h("div.wrap", f.src ? ext(f.src) : "(no source)"), h("div.meta", `${f.tag} ${f.w}×${f.h}${f.title ? ` · ${f.title}` : ""}${f.sandbox != null ? " · sandboxed" : ""}`))))), { count: r.iframes.length, open: false }));

  // --- Scripts --------------------------------------------------------------------------
  const extScripts = r.scripts.filter((s) => s.src);
  if (extScripts.length) out.append(section("Script files", limited(extScripts, (s) => h("div.item", h("div.main", h("div.wrap", ext(s.src)), h("div.meta", [s.service, s.external ? "other site" : "same site", s.integrity ? "SRI" : s.external ? "no SRI" : null].filter(Boolean).join(" · ")))), 40), { count: extScripts.length, open: false }));

  // --- Comments -------------------------------------------------------------------------
  if (r.comments?.length) out.append(section("HTML comments", limited(r.comments, (c) => h("div.item", { class: c.flagged ? "flagged" : "" }, h("div.main.ctx.mono", c.text)), 40), { count: r.comments.length, open: r.comments.some((c) => c.flagged) }));

  if (r.meta?.og && Object.keys(r.meta.og).length) out.append(section("Social sharing tags", kv(Object.entries({ ...r.meta.og, ...r.meta.twitter }).slice(0, 40)), { open: false }));
  return out;
}

function linkRow(ctx, l) {
  const id = `link:${l.url}`;
  const locate = ctx.isCurrentTab() ? h("button.btn.tiny.ghost", { type: "button", title: "Show on the page", onclick: () => ctx.highlight(id, { value: l.url, matchHref: true, hrefOnly: true }, { focus: true }) }, "⌖") : null;
  return h("div.item", h("span.badge", { style: { minWidth: "38px", textAlign: "center" } }, l.ext || l.category),
    h("div.main",
      l.text ? h("div.wrap", l.text) : null,
      h("div.meta.wrap", /^https?:/.test(l.url) ? ext(l.url) : l.url),
      h("div.row.wrap-row", l.external ? badge("external") : null, l.notable && !l.secretParams.length ? badge(l.category, "warn") : null, l.secretParams.length ? badge(`secret in URL: ${l.secretParams.join(", ")}`, "bad") : null, l.insecure ? badge("http", "bad") : null, l.count > 1 ? badge(`${l.count}×`) : null)
    ),
    h("div.tools", locate)
  );
}
