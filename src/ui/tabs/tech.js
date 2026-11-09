// Technologies, tracking/ad IDs, third parties, cookies and JavaScript intelligence.

import { h, section, kv, empty, ext, limited, badge, copyBtn } from "../dom.js";
import { pivotsFor } from "../../core/pivots.js";
import { groupBy } from "../../core/util.js";

export function render(ctx) {
  const r = ctx.S.report;
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });

  // --- Tracking and account IDs -----------------------------------------------------
  const ids = r.indicators.filter((i) => ["tracker", "verification", "api_key_public"].includes(i.type));
  out.append(section("Tracking, advertising & account IDs", ids.length ? [
    h("p.small.muted", "These belong to the site owner's accounts. The same ID on another site is a strong sign of a common owner; use the pivots to find those sites."),
    limited(ids.sort((a, b) => Number(!!b.extra?.strong) - Number(!!a.extra?.strong)), (i) => {
      const pv = h("button.btn.tiny", { type: "button" }, "Pivot ▾");
      pv.addEventListener("click", () => ctx.pivotMenu(pv, i));
      return h("div.item", h("div.main",
        h("div.row.wrap-row", h("span.value", i.value), i.extra?.strong ? badge("links sites", "accent") : null),
        h("div.meta", `${i.label || i.type}${i.extra?.kind ? ` · ${i.extra.kind}` : ""}`),
        h("div.ctx", i.sources.slice(0, 3).join(", "))
      ), h("div.tools", copyBtn(i.value), pv));
    }, 60)
  ] : empty("No tracking or account IDs found."), { count: ids.length }));

  // --- Technologies ------------------------------------------------------------------
  const byCat = groupBy(r.tech, (t) => t.cat);
  out.append(section("Technologies", r.tech.length ? [...byCat].map(([cat, list]) => [
    h("div.group-label", cat),
    h("div.list", list.map((t) => h("div.item", { class: t.vulns.length ? "flagged" : "" }, h("div.main",
      h("div.row.wrap-row", h("b", t.name), t.version ? h("span.mono", t.version) : null, t.vulns.length ? badge("outdated", "bad") : null),
      t.vulns.map((v) => h("div.meta", `${v.summary}${v.ids.length ? ` (${v.ids.join(", ")})` : ""}${v.below !== "*" ? ` — fixed in ${v.below}` : ""}`)),
      h("div.ctx", t.evidence.slice(0, 2).join(" · "))
    ), t.version ? h("div.tools", ext(`https://cvedb.shodan.io/cves?product=${encodeURIComponent(t.name.toLowerCase().split(" ")[0])}`, "CVEs", "small")) : null)))
  ]) : empty("No technologies recognised."), { count: r.tech.length }));

  // --- Third parties ---------------------------------------------------------------------
  const tp = r.thirdParties;
  const byCategory = groupBy(tp, (t) => t.category);
  out.append(section("Third-party hosts", tp.length ? [
    h("p.small.muted", "Every other site this page loads from or links to. \"Loaded\" hosts received a request from your browser when the page opened."),
    [...byCategory].sort((a, b) => b[1].length - a[1].length).map(([cat, list]) => [
      h("div.group-label", `${cat} (${list.length})`),
      limited(list, (t) => h("div.item", h("div.main",
        h("div.row.wrap-row", h("span.value", t.host), t.service ? h("span.meta", t.service) : null, t.loaded ? badge("loaded") : badge("linked")),
        h("div.meta", Object.entries(t.kinds).map(([k, n]) => `${k} ${n}`).join(" · "))
      )), 15)
    ])
  ] : empty("The page doesn't use third-party hosts."), { count: tp.length, open: false }));

  // --- Cookies, storage, runtime --------------------------------------------------------------
  const cookieNotes = r.cookies.filter((c) => c.note);
  out.append(section("Cookies & browser storage", [
    kv([
      ["Cookies readable by scripts", r.cookies.length ? h("div.chips", r.cookies.map((c) => h("span.chip", { title: c.note || "" }, c.name))) : "none"],
      ["localStorage keys", r.storage?.local?.length ? h("div.chips", r.storage.local.slice(0, 60).map((k) => h("span.chip", k))) : "none"],
      ["sessionStorage keys", r.storage?.session?.length ? h("div.chips", r.storage.session.slice(0, 60).map((k) => h("span.chip", k))) : "none"]
    ]),
    cookieNotes.map((c) => h("div.small.check-warn", `${c.name}: ${c.note}`)),
    h("p.tiny.faint", "Only names are read, never values. HttpOnly cookies aren't visible to the extension.")
  ], { open: false }));

  if (r.runtime && (Object.keys(r.runtime.globals).length || r.runtime.ids.length)) {
    out.append(section("JavaScript runtime", kv([
      ["Detected libraries", Object.entries(r.runtime.globals).map(([k, v]) => (v === true ? k : `${k} ${v}`)).join(", ")],
      ["IDs loaded at runtime", r.runtime.ids.join(", ")],
      ["Config objects", r.runtime.configKeys.join(", ")]
    ]), { open: false }));
  }

  // --- JS intel ----------------------------------------------------------------------------------
  const js = r.js || {};
  const jsParts = [];
  if (js.buckets?.length) jsParts.push(h("div.group-label", "Cloud storage buckets"), h("div.list", js.buckets.map((b) => h("div.item", h("div.main", h("div.row", badge(b.provider), " ", h("span.value", b.name)), h("div.ctx", b.evidence), h("div.meta", b.source)), h("div.tools", copyBtn(b.name))))));
  if (js.internalHosts?.length) jsParts.push(h("div.group-label", "Internal hostnames"), h("div.chips", js.internalHosts.map((x) => h("span.chip", x))));
  if (js.preprodHosts?.length) jsParts.push(h("div.group-label", "Pre-production / internal services"), h("div.chips", js.preprodHosts.map((x) => h("span.chip", x))));
  if (js.sourcemaps?.length) jsParts.push(h("div.group-label", "Source maps"), h("div.list", js.sourcemaps.map((u) => h("div.item", h("div.main.wrap", /^https?:/.test(u) ? ext(u) : u)))));
  if (js.env?.length) jsParts.push(h("div.group-label", "Build-time environment variables"), h("div.list", js.env.map((e) => h("div.item", h("div.main", h("span.value", `${e.name} = ${e.value}`), h("div.meta", e.source))))));
  if (js.websockets?.length) jsParts.push(h("div.group-label", "WebSocket endpoints"), h("div.list", js.websockets.map((u) => h("div.item", h("div.main.value", u)))));
  if (js.endpoints?.length) jsParts.push(h("div.group-label", `API endpoints and paths (${js.endpoints.length})`), limited(js.endpoints, (e) => h("div.item", h("div.main", h("span.value", e.url), h("div.meta", e.source)), h("div.tools", copyBtn(e.url))), 40));
  if (js.comments?.length) jsParts.push(h("div.group-label", "Developer comments in scripts"), limited(js.comments, (c) => h("div.item", h("div.main", h("div.ctx", c.text), h("div.meta", c.source))), 20));
  out.append(section("What the site's JavaScript reveals", jsParts.length ? [h("p.small.muted", `${r.scriptsFetched || 0} script file(s) analysed${r.scriptsSkipped ? `, ${r.scriptsSkipped} couldn't be downloaded (other sites: grant access in Settings to include them)` : ""}, plus inline scripts.`), jsParts] : empty("Nothing notable in the page's scripts."), { open: jsParts.length > 0 && jsParts.length < 12 }));

  // --- Pivots for the site ------------------------------------------------------------------------
  out.append(section("Pivot the domain", h("div.row.wrap-row", pivotsFor({ type: "domain", value: r.page.site }).map((p) => ext(p.url, p.name, "small"))), { open: false }));
  return out;
}
