// Online enrichment: runs the selected lookups for a report's domain and IPs
// and folds the results back in as new indicators.

import { dnsProfile, mailSecurity, reverseDns } from "./dns.js";
import { rdapDomain, rdapIp } from "./rdap.js";
import { certTransparency, wayback, internetDb, asnLookup, hostingOf, urlscanSearch, gtmContainer } from "./sources.js";
import { verificationFromTxt, findTrackersInText, mergeTrackers } from "../core/trackers.js";
import { applyDomainAge } from "../core/phishing.js";
import { isPublicIP, registrableDomain } from "../core/domain.js";
import { indicatorKey } from "../core/indicators.js";
import { mapLimit } from "../core/util.js";

/** Sources and their defaults. `key` matches settings.online.<key>. */
export const ONLINE_SOURCES = [
  { key: "dns", label: "DNS records (Cloudflare / Google DNS-over-HTTPS)" },
  { key: "rdap", label: "Domain & IP registration (RDAP)" },
  { key: "asn", label: "ASN / hosting network (Team Cymru)" },
  { key: "internetdb", label: "Open ports & known CVEs (Shodan InternetDB)" },
  { key: "ct", label: "Subdomains from certificate transparency (crt.sh / Cert Spotter)" },
  { key: "wayback", label: "Archive history (Wayback Machine)" },
  { key: "urlscan", label: "Previous public scans (urlscan.io)" },
  { key: "gtm", label: "Google Tag Manager container contents" }
];

/** Add an indicator to a stored report's plain indicator list (no IndicatorBag in storage). */
export function addIndicator(report, type, value, o = {}) {
  if (!value) return;
  const k = indicatorKey(type, value);
  let ind = report.indicators.find((i) => i.type === type && indicatorKey(i.type, i.value) === k);
  if (!ind) {
    ind = { type, value: String(value), label: o.label || null, count: 0, sources: [], contexts: [], extra: { ...(o.extra || {}) }, confidence: o.confidence || "high" };
    report.indicators.push(ind);
    report.counts[type] = (report.counts[type] || 0) + 1;
  } else if (o.extra) Object.assign(ind.extra, o.extra);
  ind.count++;
  if (o.source && !ind.sources.includes(o.source)) ind.sources.push(o.source);
  if (o.label && !ind.label) ind.label = o.label;
}

/**
 * Run online lookups.
 * @param {object} report    stored report (mutated: indicators, online, phishing)
 * @param {object} enabled   { dns: true, rdap: true, ... }
 * @param {object} [o]       { signal, onProgress(text), urlscanKey }
 */
export async function enrich(report, enabled, o = {}) {
  const domain = report.page.site;
  const host = report.page.host;
  const online = report.online || {};
  const errors = [];
  const step = async (key, label, fn) => {
    if (!enabled[key]) return;
    o.onProgress?.(label);
    try {
      await fn();
    } catch (e) {
      errors.push({ source: key, message: e.message || String(e) });
    }
  };
  const opt = { signal: o.signal };

  await Promise.all([
    step("dns", "DNS records", async () => {
      const prof = await dnsProfile(domain, host, opt);
      online.dns = prof;
      online.mail = mailSecurity(prof);
      for (const ip of [...prof.A, ...prof.AAAA, ...(prof.apexA || [])]) addIndicator(report, "ip", ip, { source: "DNS", label: "Resolved address" });
      for (const ns of prof.NS) addIndicator(report, "host", ns, { source: "DNS NS", label: "Name server" });
      for (const mx of prof.MX) addIndicator(report, "host", mx.split(/\s+/).pop(), { source: "DNS MX", label: "Mail server" });
      for (const c of prof.CNAME) addIndicator(report, "host", c, { source: "DNS CNAME", label: "CNAME target" });
      for (const t of prof.TXT) {
        const v = verificationFromTxt(t);
        if (v) addIndicator(report, "verification", v.token, { source: "DNS TXT", label: v.service, extra: { service: v.service } });
      }
      for (const inc of online.mail.spfIncludes) addIndicator(report, "domain", registrableDomain(inc), { source: "SPF include", confidence: "medium" });
      for (const em of online.mail.dmarcReports) addIndicator(report, "email", em.toLowerCase(), { source: "DMARC report address" });
    }),
    step("rdap", "Domain registration", async () => {
      online.rdap = await rdapDomain(domain, opt);
      const r = online.rdap;
      if (r?.found) {
        if (r.registrant?.org) addIndicator(report, "organization", r.registrant.org, { source: "RDAP registrant" });
        if (r.registrant?.name && r.registrant.name !== r.registrant.org) addIndicator(report, "organization", r.registrant.name, { source: "RDAP registrant", confidence: "medium" });
        if (r.registrant?.email) addIndicator(report, "email", r.registrant.email.toLowerCase(), { source: "RDAP registrant" });
        for (const ns of r.nameservers) addIndicator(report, "host", ns, { source: "RDAP", label: "Name server" });
        if (typeof r.ageDays === "number") report.phishing = applyDomainAge(report.phishing, r.ageDays);
      }
    }),
    step("ct", "Certificate transparency", async () => {
      online.ct = await certTransparency(domain, { ...opt, timeoutMs: 45000 });
      for (const h of online.ct.subdomains.slice(0, 400)) addIndicator(report, "host", h, { source: "certificate transparency", confidence: "medium" });
    }),
    step("wayback", "Wayback Machine", async () => {
      online.wayback = await wayback(host, opt);
    }),
    step("urlscan", "urlscan.io", async () => {
      online.urlscan = await urlscanSearch(domain, { ...opt, apiKey: o.urlscanKey });
      for (const ip of online.urlscan.ips) addIndicator(report, "ip", ip, { source: "urlscan.io history", confidence: "medium" });
    }),
    step("gtm", "Tag Manager containers", async () => {
      const ids = report.indicators.filter((i) => i.type === "tracker" && /^GTM-/.test(i.value)).map((i) => i.value).slice(0, 5);
      if (!ids.length) return;
      const found = [];
      for (const id of ids) {
        const c = await gtmContainer(id, opt).catch(() => null);
        if (!c) continue;
        const hits = mergeTrackers(findTrackersInText(c.text, `GTM container ${id}`)).filter((h) => h.rule !== "gtm" || h.value !== id);
        found.push({ id, ids: hits.map((h) => ({ vendor: h.vendor, value: h.value })) });
        for (const h of hits) {
          const isKey = ["api key", "payments", "maps", "captcha"].includes(h.kind);
          addIndicator(report, isKey ? "api_key_public" : "tracker", h.value, { source: `GTM container ${id}`, label: h.vendor, extra: { rule: h.rule, kind: h.kind, strong: h.strong } });
          if (!report.trackers.some((t) => t.rule === h.rule && t.value === h.value)) report.trackers.push({ ...h, sources: [`GTM container ${id}`] });
        }
      }
      online.gtm = found;
    })
  ]);

  // Per-IP enrichment once DNS has resolved addresses.
  const ips = [...new Set(report.indicators.filter((i) => i.type === "ip" && isPublicIP(i.value) && i.sources.some((s) => /DNS|page URL/.test(s))).map((i) => i.value))].slice(0, 8);
  if (ips.length && (enabled.asn || enabled.internetdb || enabled.rdap || enabled.dns)) {
    o.onProgress?.(`IP intelligence (${ips.length})`);
    online.ips = await mapLimit(ips, 4, async (ip) => {
      const entry = { ip };
      await Promise.all([
        enabled.dns && reverseDns(ip, opt).then((p) => (entry.ptr = p)).catch(() => {}),
        enabled.asn && asnLookup(ip, opt).then((a) => {
          entry.asn = a;
          if (a) {
            entry.hosting = hostingOf(a.name);
            addIndicator(report, "asn", `AS${a.asn}`, { source: `ASN of ${ip}`, label: a.name || null });
          }
        }).catch((e) => errors.push({ source: "asn", message: `${ip}: ${e.message}` })),
        enabled.internetdb && internetDb(ip, opt).then((d) => {
          entry.internetdb = d;
          for (const v of d?.vulns || []) addIndicator(report, "cve", v, { source: `InternetDB ${ip}`, confidence: "medium" });
          for (const h of d?.hostnames || []) addIndicator(report, "host", h, { source: `InternetDB ${ip}`, confidence: "low" });
        }).catch((e) => errors.push({ source: "internetdb", message: `${ip}: ${e.message}` })),
        enabled.rdap && rdapIp(ip, opt).then((r) => {
          entry.rdap = r;
          if (r?.org) addIndicator(report, "organization", r.org, { source: `IP owner ${ip}`, label: "Network owner", confidence: "medium" });
        }).catch((e) => errors.push({ source: "rdap", message: `${ip}: ${e.message}` }))
      ]);
      return entry;
    });
  }

  online.errors = errors;
  online.ranAt = new Date().toISOString();
  online.sources = Object.keys(enabled).filter((k) => enabled[k]);
  report.online = online;
  return report;
}
