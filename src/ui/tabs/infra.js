// Infrastructure: response headers, DNS, mail security, registration, IPs,
// certificate transparency, archive history and the site's well-known files.

import { h, section, kv, empty, ext, limited, fmtDay, fmtDate, badge, copyBtn, send, toast } from "../dom.js";
import { pivotsFor } from "../../core/pivots.js";

const statusIcon = { pass: "✓", warn: "!", fail: "✗", info: "·" };

export function render(ctx) {
  const r = ctx.S.report;
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const on = r.online;
  const job = ctx.S.job.online;

  if (!on) {
    out.append(h("div.notice.info", h("div.grow",
      h("b", "Online lookups haven't run yet. "),
      "They query public sources (DNS over HTTPS, RDAP, certificate transparency, the Wayback Machine, Shodan InternetDB, urlscan.io, Team Cymru) about this domain and its IPs. The target site itself isn't contacted."),
      h("button.btn.small.primary", { type: "button", disabled: job?.status === "running", onclick: () => send("online", { reportId: r.id }).catch((e) => toast(e.message, "error")) }, job?.status === "running" ? job.step || "Running…" : "Run lookups")));
  } else if (on.errors?.length) {
    out.append(h("div.notice.warn", h("div", h("b", "Some lookups failed: "), on.errors.map((e) => `${e.source}: ${e.message}`).join("; "))));
  }

  // --- Response headers ------------------------------------------------------------
  if (r.headers) {
    const hd = r.headers;
    out.append(section(["Security headers ", h(`span.grade.grade-${hd.grade}`, hd.grade)], [
      h("div.list", hd.checks.map((c) => h("div.item", h(`span.check-${c.status}`, { style: { fontWeight: 800, width: "14px" } }, statusIcon[c.status]), h("div.main", h("b", c.title), h("div.meta", c.note), c.value ? h("div.ctx.mono", c.value.slice(0, 400)) : null)))),
      hd.leaks.length ? [h("div.group-label", "Headers that reveal infrastructure"), h("div.list", hd.leaks.map((l) => h("div.item", h("div.main", h("span.value", `${l.header}: ${l.value}`), l.note ? h("div.meta", l.note) : null))))] : null,
      hd.cspHosts.length ? [h("div.group-label", `Hosts allowed by the Content-Security-Policy (${hd.cspHosts.length})`), h("div.chips", hd.cspHosts.map((x) => h("span.chip", x)))] : null
    ]));
    out.append(section("All response headers", h("table.grid", h("tbody", Object.entries(r.response?.headers || {}).sort().map(([k, v]) => h("tr", h("th", k), h("td.mono", v))))), { open: false, count: Object.keys(r.response?.headers || {}).length }));
  } else {
    out.append(h("div.notice", "Response headers weren't available (the page may not be served over HTTP, or the re-fetch was blocked)."));
  }

  if (on?.dns) {
    const d = on.dns;
    const rec = (label, list) => (list?.length ? [label, h("div", list.map((x) => h("div.mono.wrap", x)))] : null);
    out.append(section("DNS", kv([rec(`A (${d.target})`, d.A), rec("AAAA", d.AAAA), rec("CNAME", d.CNAME), rec("A (apex)", d.apexA), rec("NS", d.NS), rec("MX", d.MX), rec("TXT", d.TXT), rec("CAA", d.CAA), rec("SOA", d.SOA)])));
  }
  if (on?.mail) {
    const m = on.mail;
    out.append(section("Email security", [
      kv([["Providers", m.providers.join(", ") || "unknown"], ["SPF", m.spf ? h("span.mono.wrap", m.spf) : h("span.check-fail", "none")], ["SPF includes", m.spfIncludes.join(", ")], ["DMARC", m.dmarc ? h("span.mono.wrap", m.dmarc) : h("span.check-fail", "none")], ["DMARC reports to", m.dmarcReports.join(", ")], ["MTA-STS", m.mtaSts ? "yes" : "no"], ["BIMI", m.bimi]]),
      m.findings.length ? h("div.list", m.findings.map((f) => h("div.item", h(`span.sev.sev-${f.severity}`, f.severity), h("div.main", f.text)))) : null
    ]));
  }
  if (on?.rdap) {
    const d = on.rdap;
    out.append(section("Domain registration (RDAP)", d.found ? kv([
      ["Domain", d.domain],
      ["Created", d.created ? `${fmtDay(d.created)} (${d.ageDays} days ago)` : null],
      ["Updated", fmtDay(d.updated)],
      ["Expires", fmtDay(d.expires)],
      ["Registrar", d.registrar ? `${d.registrar}${d.registrarIanaId ? ` (IANA ${d.registrarIanaId})` : ""}` : null],
      ["Status", d.status.join(", ")],
      ["Name servers", d.nameservers.join(", ")],
      ["DNSSEC", d.dnssec == null ? null : d.dnssec ? "signed" : "not signed"],
      ["Registrant", d.registrant ? d.registrant.redacted ? "redacted for privacy" : [d.registrant.name, d.registrant.org, d.registrant.email, d.registrant.address].filter(Boolean).join(" · ") : null],
      ["Abuse contact", d.abuseEmail],
      ["Source", d.source ? ext(d.source) : null]
    ]) : empty("No RDAP record found (some country domains don't offer RDAP).")));
  }
  if (on?.ips?.length) {
    out.append(section("IP addresses", h("div.list", on.ips.map((ip) => h("div.item", h("div.main",
      h("div.row.wrap-row", h("span.value", ip.ip), ip.hosting ? badge(ip.hosting, "accent") : null, ip.internetdb?.tags?.map((t) => badge(t))),
      kv([
        ["Network", ip.asn ? `AS${ip.asn.asn} ${ip.asn.name || ""} · ${ip.asn.prefix} · ${ip.asn.country}` : null],
        ["Owner", ip.rdap ? [ip.rdap.org, ip.rdap.name, ip.rdap.range].filter(Boolean).join(" · ") : null],
        ["Abuse", ip.rdap?.abuseEmail],
        ["Reverse DNS", ip.ptr?.join(", ")],
        ["Open ports", ip.internetdb?.ports?.join(", ")],
        ["Software", ip.internetdb?.cpes?.slice(0, 10).join(", ")],
        ["Known CVEs", ip.internetdb?.vulns?.length ? `${ip.internetdb.vulns.length}: ${ip.internetdb.vulns.slice(0, 8).join(", ")}` : null],
        ["Other hostnames", ip.internetdb?.hostnames?.slice(0, 8).join(", ")]
      ]),
      h("div.row.wrap-row", pivotsFor({ type: "ip", value: ip.ip }).slice(0, 6).map((p) => ext(p.url, p.name, "small")))
    )))), { count: on.ips.length, open: on.ips.length <= 3 }));
  }
  if (on?.ct) {
    const ct = on.ct;
    const q = h("input", { type: "search", placeholder: "Filter subdomains…" });
    const list = h("div");
    const draw = () => {
      const s = q.value.trim().toLowerCase();
      const items = ct.subdomains.filter((x) => !s || x.includes(s));
      list.replaceChildren(limited(items, (x) => h("div.item", { class: ct.interesting.includes(x) ? "flagged" : "" }, h("div.main.value", x), h("div.tools", ext(`https://${x}/`, "open", "small"), copyBtn(x))), 60));
    };
    q.addEventListener("input", draw);
    draw();
    out.append(section(`Subdomains from certificate transparency (${ct.source})`, [
      kv([["Names", String(ct.subdomains.length)], ["Notable", ct.interesting.slice(0, 20).join(", ") || "none"], ["Wildcard certificates", ct.wildcard ? "yes" : "no"], ["Issuers", ct.issuers.map((i) => `${i.name} (${i.count})`).join(", ")], ["First certificate", fmtDay(ct.first)], ["Latest certificate", fmtDay(ct.last)]]),
      ct.subdomains.length ? [q, list] : null
    ], { count: ct.subdomains.length }));
  }
  if (on?.wayback) {
    const w = on.wayback;
    out.append(section("Archive history (Wayback Machine)", [
      kv([["First archived", w.firstSeen || "never"], ["Last archived", w.lastSeen], ["Archived URLs", w.urlCount ? `${w.urlCount}${w.capped ? "+" : ""}` : null], ["Common file types", w.topExtensions.map((e) => `.${e.ext} (${e.count})`).join(", ")], ["Browse", ext(w.browse, "Open in the Wayback Machine")]]),
      w.files.length ? [h("div.group-label", `Archived documents and data files (${w.files.length})`), limited(w.files, (f) => h("div.item", h("div.main", h("div.row", h("span.badge", f.ext), " ", ext(f.archived, f.url.replace(/^https?:\/\//, ""))), h("div.meta", `${f.date} · ${f.category}`))), 40)] : null
    ]));
  }
  if (on?.urlscan) {
    const u = on.urlscan;
    out.append(section("Previous public scans (urlscan.io)", u.results.length ? limited(u.results, (s) => h("div.item", h("div.main",
      h("div.wrap", ext(s.result?.replace("/api/v1/result/", "/result/") || s.url, s.url)),
      h("div.meta", `${fmtDate(s.time)} · ${s.ip || "?"} · ${s.asnname || ""} · ${s.server || ""} · HTTP ${s.status || "?"}`),
      s.title ? h("div.ctx", s.title) : null
    )), 15) : empty("No public scans found."), { count: u.total }));
  }
  if (on?.gtm?.length) {
    out.append(section("Google Tag Manager containers", h("div.list", on.gtm.map((g) => h("div.item", h("div.main", h("b", g.id), h("div.meta", g.ids.length ? g.ids.map((x) => `${x.vendor}: ${x.value}`).join(" · ") : "No other IDs inside")))))));
  }

  // --- Well-known files --------------------------------------------------------------
  const wk = r.wellKnown || {};
  const files = [];
  if (wk.robots) files.push(h("div.item", h("div.main", h("b", "robots.txt"), kv([["Disallowed paths", String(wk.robots.disallow.length)], ["Interesting", wk.robots.interesting.length ? h("div", wk.robots.interesting.slice(0, 40).map((p) => h("div.mono", p))) : "none"], ["Sitemaps", wk.robots.sitemaps.join(", ")], ["User agents", wk.robots.userAgents.slice(0, 12).join(", ")]]))));
  if (wk.sitemap) files.push(h("div.item", h("div.main", h("b", "sitemap.xml"), kv([["Entries", String(wk.sitemap.count)], ["Index of sitemaps", wk.sitemap.isIndex ? "yes" : "no"], ["Oldest change", wk.sitemap.oldest], ["Newest change", wk.sitemap.newest]]))));
  if (wk.securityTxt) files.push(h("div.item", h("div.main", h("b", "security.txt"), wk.securityTxt.expired ? badge("expired", "warn") : null, kv(Object.entries(wk.securityTxt.fields).map(([k, v]) => [k, v.join(", ")])))));
  if (wk.humansTxt) files.push(h("div.item", h("div.main", h("b", "humans.txt"), h("pre.result-pre", wk.humansTxt.slice(0, 1500)))));
  for (const [k, label] of [["ads", "ads.txt"], ["appAds", "app-ads.txt"]]) {
    if (!wk[k]) continue;
    files.push(h("div.item", h("div.main", h("b", label), kv([["Records", String(wk[k].records)], ["Direct accounts (the owner's own)", wk[k].direct.length ? h("div", wk[k].direct.slice(0, 20).map((d) => h("div.mono", `${d.system}: ${d.account}`))) : "none"], ["Resellers", String(wk[k].resellers)], ["Owner domain", wk[k].vars.ownerdomain?.join(", ")]]))));
  }
  if (wk.manifest) files.push(h("div.item", h("div.main", h("b", "Web app manifest"), kv([["Name", wk.manifest.name], ["Short name", wk.manifest.shortName], ["Start URL", wk.manifest.startUrl], ["Related apps", wk.manifest.relatedApps.map((a) => `${a.platform}: ${a.id || a.url}`).join(", ")]]))));
  out.append(section("The site's public files", files.length ? h("div.list", files) : empty("None of robots.txt, sitemap.xml, security.txt, humans.txt, ads.txt or a manifest were found."), { count: files.length }));

  // --- Favicon ---------------------------------------------------------------------------
  if (r.favicon) {
    const f = r.favicon;
    const ind = { type: "favicon", value: String(f.mmh3), extra: { mmh3: f.mmh3, md5: f.md5, sha256: f.sha256 } };
    out.append(section("Favicon fingerprint", [
      h("div.row", h("img", { src: f.url, alt: "", width: 32, height: 32, referrerpolicy: "no-referrer", style: { borderRadius: "4px" } }), h("div.small.muted.wrap", f.url)),
      kv([["MurmurHash3 (Shodan)", h("span.mono", String(f.mmh3))], ["MD5", h("span.mono", f.md5)], ["SHA-256", h("span.mono.wrap", f.sha256)], ["Size", `${f.size} bytes`]]),
      h("div.small.muted", "Search engines for internet-facing servers index favicons. The same hash elsewhere can reveal the origin server behind a CDN, staging hosts or sibling phishing sites. Default framework icons match millions of servers."),
      h("div.row.wrap-row", pivotsFor(ind).map((p) => ext(p.url, p.name, "small")), copyBtn(f.queries.shodan, "Copy Shodan query"))
    ]));
  }
  return out;
}
