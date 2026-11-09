// Files: download images and documents the page uses or links to and read
// their metadata (EXIF/GPS, XMP, IPTC, PDF and Office properties).

import { h, section, empty, ext, limited, badge, send, toast } from "../dom.js";
import { formatBytes } from "../../core/util.js";
import { CATEGORIES } from "../../core/links.js";

const DOC_EXT = new Set(["pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods", "odp", "rtf"]);

export function live(ctx) {
  const j = ctx.S.job.files;
  if (j?.status === "running") return h("div.notice", { dataset: { live: "files" } }, h("div.spin"), h("div.grow", `Analysing files… ${j.done || 0} of ${j.total}`), h("button.btn.small", { type: "button", onclick: () => send("cancel", { reportId: ctx.S.report.id, slot: "files" }) }, "Cancel"));
  if (j?.status === "error") return h("div.notice.error", { dataset: { live: "files" } }, j.error);
  return h("div", { dataset: { live: "files" } });
}

export function render(ctx) {
  const r = ctx.S.report;
  const ui = (ctx.S.ui.files ||= { selected: new Set() });
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const done = new Map((r.files || []).map((f) => [f.url, f]));

  const imgs = (r.images || []).filter((i) => /^https?:/.test(i.src) && !/\.svg(\?|$)/i.test(i.src)).map((i) => ({ url: i.src, label: i.alt || i.src.split("/").pop().split("?")[0], kind: "image", w: i.w, h: i.h }));
  const docs = r.links.filter((l) => DOC_EXT.has(l.ext) || (CATEGORIES.image.includes(l.ext) && /^https?:/.test(l.url))).map((l) => ({ url: l.url, label: l.text || l.url.split("/").pop(), kind: DOC_EXT.has(l.ext) ? "document" : "image", ext: l.ext }));
  const candidates = [...docs, ...imgs].filter((c, i, a) => a.findIndex((x) => x.url === c.url) === i);
  // Larger photos are most likely to carry camera metadata.
  candidates.sort((a, b) => Number(b.kind === "document") - Number(a.kind === "document") || (b.w * b.h || 0) - (a.w * a.h || 0));

  out.append(live(ctx));
  const analyze = async (urls) => {
    if (!urls.length) return toast("Select files first.");
    const origins = [...new Set(urls.map((u) => new URL(u).origin))].filter((o) => o !== new URL(r.page.url).origin);
    if (origins.length) {
      const has = await chrome.permissions.contains({ origins: origins.map((o) => `${o}/*`) });
      if (!has && !(await ctx.requestHostAccess(origins.map((o) => `${o}/*`)))) toast("Files on other sites may fail without access.");
    }
    send("files", { reportId: r.id, urls, tabId: ctx.isCurrentTab() ? ctx.S.tabId : null }).catch((e) => toast(e.message, "error"));
  };

  // --- Results --------------------------------------------------------------------------
  const results = r.files || [];
  if (results.length) {
    out.append(section("Metadata found", h("div.list", results.map((f) => fileResult(f))), { count: results.length }));
  }

  // --- Picker -------------------------------------------------------------------------------
  const selectAll = (list) => {
    for (const c of list) if (!done.has(c.url)) ui.selected.add(c.url);
    ctx.rerender();
  };
  const pick = (c) => {
    const box = h("input", { type: "checkbox", checked: ui.selected.has(c.url), onchange: (e) => (e.target.checked ? ui.selected.add(c.url) : ui.selected.delete(c.url)) });
    return h("div.item", box,
      c.kind === "image" ? h("img", { src: c.url, alt: "", loading: "lazy", referrerpolicy: "no-referrer", style: { width: "40px", height: "40px", objectFit: "cover", borderRadius: "4px", flex: "none" } }) : h("span.badge", { style: { minWidth: "40px", textAlign: "center" } }, c.ext || "doc"),
      h("div.main", h("div.wrap.small", c.label), h("div.meta.wrap", c.url), done.has(c.url) ? badge(done.get(c.url).error ? "failed" : "analysed", done.get(c.url).error ? "bad" : "good") : null, c.w ? h("span.meta", ` ${c.w}×${c.h}`) : null)
    );
  };
  out.append(section("Choose files to analyse", candidates.length ? [
    h("p.small.muted", "Files are downloaded by the extension and parsed locally. Photos often keep GPS position, camera serial numbers and owner names; documents keep author and user names, company, software and file-server paths."),
    h("div.row.wrap-row",
      h("button.btn.small.primary", { type: "button", disabled: ctx.S.job.files?.status === "running", onclick: () => analyze([...ui.selected]) }, `Analyse selected`),
      h("button.btn.small", { type: "button", onclick: () => selectAll(candidates.filter((c) => c.kind === "document")) }, "Select documents"),
      h("button.btn.small", { type: "button", onclick: () => selectAll(candidates.filter((c) => c.kind === "image").slice(0, 40)) }, "Select 40 largest images"),
      h("button.btn.small.ghost", { type: "button", onclick: () => (ui.selected.clear(), ctx.rerender()) }, "Clear")
    ),
    limited(candidates, pick, 60)
  ] : empty("No images or documents found on this page."), { count: candidates.length }));

  const manual = h("input", { type: "url", placeholder: "Or paste a file URL (image, PDF, Office document)…" });
  out.append(h("div.card.row", manual, h("button.btn.small", { type: "button", onclick: () => manual.value && analyze([manual.value.trim()]) }, "Analyse")));
  return out;
}

function fileResult(f) {
  const name = f.url.split("/").pop().split("?")[0] || f.url;
  const rows = f.rows || [];
  const sensitive = rows.filter((x) => x.sensitive).length;
  return h("div.item", h("div.main",
    h("div.row.wrap-row", h("b.wrap", name), f.format ? badge(f.format) : null, f.gps ? badge("GPS", "bad") : null, sensitive ? badge(`${sensitive} identifying`, "warn") : null, f.error ? badge("failed", "bad") : null),
    h("div.meta.wrap", ext(f.url)),
    f.error ? h("div.small.check-fail", f.error) : null,
    f.gps ? h("div.small", "Taken at ", h("b", `${f.gps.lat}, ${f.gps.lon}`), " · ", ext(`https://www.google.com/maps/search/?api=1&query=${f.gps.lat},${f.gps.lon}`, "Google Maps"), " · ", ext(`https://www.openstreetmap.org/?mlat=${f.gps.lat}&mlon=${f.gps.lon}#map=17/${f.gps.lat}/${f.gps.lon}`, "OpenStreetMap")) : null,
    (f.warnings || []).map((w) => h("div.small.check-warn", w)),
    rows.length ? h("table.grid", h("tbody", rows.slice(0, 80).map((x) => h("tr", { class: x.sensitive ? "sensitive" : "" }, h("th", `${x.group} · ${x.name}`), h("td", x.value))))) : f.error ? null : h("div.small.faint", "No metadata in this file."),
    f.sha256 ? h("div.tiny.faint.mono.wrap", `SHA-256 ${f.sha256}${f.size ? ` · ${formatBytes(f.size)}` : ""}`) : null
  ));
}
