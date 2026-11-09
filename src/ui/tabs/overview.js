// Overview: the most important findings at a glance, links to past
// investigations, identity, a relationship graph, and notes.

import { h, section, kv, empty, ext, sev, badge, fmtDay, send, toast } from "../dom.js";
import { INDICATOR_TYPES } from "../../core/indicators.js";
import { relationshipGraph } from "../graph.js";

export function render(ctx) {
  const r = ctx.S.report;
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });

  // --- Highlights ------------------------------------------------------------
  const hl = [];
  const add = (level, text, tab) => hl.push(h("div.item", sev(level), h("div.main", tab ? h("a", { href: "#", onclick: (e) => (e.preventDefault(), ctx.setTab(tab)) }, text) : text)));
  const crit = r.exposures.filter((e) => e.severity === "critical" || e.severity === "high");
  if (crit.length) add(crit.some((e) => e.severity === "critical") ? "critical" : "high", `${crit.length} likely exposed secret(s) or personal data: ${[...new Set(crit.map((e) => e.label))].slice(0, 3).join(", ")}`, "exposures");
  for (const s of (r.phishing?.signals || []).filter((s) => s.weight >= 15).slice(0, 4)) add(s.weight >= 25 ? "high" : "medium", `${s.title}${s.detail ? ` — ${s.detail}` : ""}`);
  const vulnTech = r.tech.filter((t) => t.vulns.length);
  if (vulnTech.length) add("medium", `Outdated software: ${vulnTech.map((t) => `${t.name} ${t.version || ""}`.trim()).join(", ")}`, "tech");
  const strong = r.indicators.filter((i) => (i.type === "tracker" && i.extra?.strong) || i.type === "verification");
  if (strong.length) add("info", `${strong.length} account-level IDs that can link this site to others (analytics, ads, verification): ${strong.slice(0, 4).map((i) => i.value).join(", ")}`, "tech");
  if (r.js?.internalHosts?.length || r.js?.preprodHosts?.length) add("low", `JavaScript references internal or pre-production hosts: ${[...r.js.internalHosts, ...r.js.preprodHosts].slice(0, 4).join(", ")}`, "tech");
  if (r.js?.sourcemaps?.length) add("low", `${r.js.sourcemaps.length} source map reference(s): original source code may be downloadable`, "tech");
  if (r.js?.buckets?.length) add("low", `Cloud storage buckets referenced: ${r.js.buckets.map((b) => b.name).slice(0, 4).join(", ")}`, "tech");
  const notableLinks = r.links.filter((l) => l.notable);
  if (notableLinks.length) add("low", `${notableLinks.length} linked file(s) worth checking (documents, data, configs, archives)`, "links");
  const flaggedComments = (r.comments || []).filter((c) => c.flagged);
  if (flaggedComments.length) add("low", `${flaggedComments.length} developer comment(s) in the HTML`, "links");
  if (r.headers && ["D", "F"].includes(r.headers.grade)) add("low", `Weak security headers (grade ${r.headers.grade})`, "infra");
  if (r.online?.mail?.findings?.length) for (const f of r.online.mail.findings.slice(0, 2)) add(f.severity, f.text, "infra");
  if (r.online?.rdap?.ageDays != null && r.online.rdap.ageDays < 180) add(r.online.rdap.ageDays < 30 ? "high" : "medium", `Domain is only ${r.online.rdap.ageDays} days old`, "infra");
  if (r.wellKnown?.robots?.interesting?.length) add("info", `robots.txt hides ${r.wellKnown.robots.interesting.length} interesting path(s): ${r.wellKnown.robots.interesting.slice(0, 3).join(", ")}`, "infra");
  if (r.ai?.result?.verdict) hl.unshift(h("div.item", sev(r.ai.result.risk_level), h("div.main", h("a", { href: "#", onclick: (e) => (e.preventDefault(), ctx.setTab("ai")) }, `AI verdict: ${r.ai.result.verdict}`))));
  out.append(section("Highlights", hl.length ? h("div.list", hl) : empty("Nothing stands out. Check the other tabs, run online lookups or ask the AI."), { count: hl.length }));

  // --- Correlations ------------------------------------------------------------
  if (r.correlations?.length) {
    out.append(section("Seen in your earlier investigations", h("div.list", r.correlations.slice(0, 40).map((c) =>
      h("div.item", h("div.main",
        h("div", badge(INDICATOR_TYPES[c.type] || c.type, "accent"), " ", h("span.value", c.value), c.label ? h("span.meta", ` ${c.label}`) : null),
        h("div.meta", "Also on: ", c.others.slice(0, 8).map((o, i) => [i ? ", " : "", h("a", { href: "#", onclick: (e) => (e.preventDefault(), ctx.openReport(o.reportId)) }, o.site)]))
      ))
    )), { count: r.correlations.length }));
  }

  // --- Identity --------------------------------------------------------------------
  const idRows = [];
  for (const e of r.identity || []) {
    idRows.push(h("div.item", h("div.main",
      h("div", h("b", e.legalName || e.name || "(unnamed)"), " ", badge(e.type)),
      kv([["Email", e.email], ["Phone", e.telephone], ["Address", e.address], ["Website", e.url], ["IDs", Object.entries(e.ids || {}).map(([k, v]) => `${k}: ${v}`).join(", ")], ["People", e.founders?.join(", ")], ["Profiles", e.sameAs?.length ? h("div", e.sameAs.slice(0, 12).map((s) => h("div", ext(s)))) : null]])
    )));
  }
  const rd = r.online?.rdap;
  if (rd?.found && rd.registrant && !rd.registrant.redacted) idRows.push(h("div.item", h("div.main", h("div", h("b", "Domain registrant"), " ", badge("RDAP")), kv([["Name", rd.registrant.name], ["Organisation", rd.registrant.org], ["Email", rd.registrant.email], ["Address", rd.registrant.address]]))));
  const orgs = r.indicators.filter((i) => i.type === "organization" || i.type === "person");
  if (orgs.length) idRows.push(h("div.item", h("div.main", h("div.meta", "Names found: "), h("div.chips", orgs.slice(0, 20).map((o) => h("span.chip", { title: o.sources.join(", ") }, o.value))))));
  const m = r.meta || {};
  idRows.push(kv([
    ["Site name", m.applicationName],
    ["Description", m.description],
    ["Author", m.author],
    ["Language", r.page.lang],
    ["Canonical URL", m.canonical ? [ext(m.canonical), m.canonicalOffsite ? h("span.badge.warn", " other site") : null] : null],
    ["Generator", m.generator],
    ["Last modified", r.page.lastModified],
    ["rel=me", m.relMe?.length ? h("div", m.relMe.map((u) => h("div", ext(u)))) : null],
    ["Feeds", m.feeds?.length ? h("div", m.feeds.map((u) => h("div", ext(u)))) : null],
    ["Other languages", m.alternates?.length ? `${m.alternates.length} (${[...new Set(m.alternates.map((a) => a.lang))].slice(0, 8).join(", ")})` : null]
  ]));
  out.append(section("Identity", idRows));

  // --- Graph ------------------------------------------------------------------------
  out.append(section("Relationship graph", relationshipGraph(r, ctx), { open: false }));

  // --- Quick facts ---------------------------------------------------------------------
  const ips = r.online?.ips || [];
  out.append(section("Quick facts", kv([
    ["Domain age", rd?.created ? `${fmtDay(rd.created)} (${rd.ageDays} days)` : r.online ? "unknown" : "run online lookups"],
    ["Registrar", rd?.registrar],
    ["Hosting", ips.map((i) => i.hosting || i.asn?.name).filter(Boolean).filter((x, i, a) => a.indexOf(x) === i).join(", ") || null],
    ["Mail", r.online?.mail?.providers?.join(", ") || null],
    ["CMS / framework", r.tech.filter((t) => /CMS|Site builder|E-commerce|JavaScript framework|Static site/.test(t.cat)).map((t) => `${t.name}${t.version ? ` ${t.version}` : ""}`).join(", ") || null],
    ["Server / CDN", r.tech.filter((t) => /Web server|CDN|Hosting|WAF|Proxy/.test(t.cat)).map((t) => t.name).join(", ") || null],
    ["First archived", r.online?.wayback?.firstSeen || null],
    ["Third parties loaded", String(r.thirdParties.filter((t) => t.loaded).length)],
    ["Page size", `${Math.round((r.page.htmlLength || 0) / 1024)} KB HTML, ${r.page.elementCount || "?"} elements${r.page.hiddenTextLength > 2000 ? `, ${Math.round(r.page.hiddenTextLength / 1024)} KB hidden text` : ""}`],
    ["Frames", r.page.frames ? `${r.page.frames.sameOrigin} same-origin, ${r.page.frames.crossOrigin} cross-origin (not scanned)` : null]
  ])));

  // --- Notes ---------------------------------------------------------------------------
  const notes = h("textarea", { rows: 4, placeholder: "Notes for this investigation (saved locally)…", value: r.notes || "" });
  const tags = h("input", { type: "text", placeholder: "Tags, comma separated", value: (r.tags || []).join(", ") });
  const star = h("label.check", h("input", { type: "checkbox", checked: !!r.starred }), h("span", "Keep this report (never auto-deleted from history)"));
  const save = h("button.btn.small.primary", { type: "button" }, "Save notes");
  save.addEventListener("click", async () => {
    try {
      await send("updateReport", { reportId: r.id, patch: { notes: notes.value, tags: tags.value.split(",").map((t) => t.trim()).filter(Boolean), starred: star.querySelector("input").checked } });
      toast("Saved");
    } catch (e) {
      toast(e.message, "error");
    }
  });
  out.append(section("Notes", [notes, tags, star, h("div", save)], { open: !!r.notes }));
  return out;
}
