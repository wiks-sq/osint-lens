// Turns raw page data (from the collector, the main-world probe and same-origin
// fetches) into the report the UI shows. Pure: no chrome.* APIs, no network.

import { IndicatorBag } from "./indicators.js";
import { extractFromText, addUrl, addHost } from "./entities.js";
import { scanExposures, urlSecrets } from "./exposures.js";
import { findTrackersInText, findTrackersInUrl, mergeTrackers, VERIFICATION_META } from "./trackers.js";
import { detectTech } from "./tech.js";
import { analyzeHeaders, analyzeCookies } from "./headers.js";
import { analyzeLinks, thirdParties, classifyHost } from "./links.js";
import { phishingScore } from "./phishing.js";
import { parseRobots, parseSitemap, parseSecurityTxt, parseAdsTxt, parseManifest, parseHumans } from "./wellknown.js";
import { analyzeScripts, analyzeComments } from "./jsintel.js";
import { registrableDomain, toUnicode, isPunycode } from "./domain.js";
import { safeUrl, bySeverity, squash } from "./util.js";

export const REPORT_VERSION = 2;

/** Parse JSON-LD blocks into a flat list of typed nodes. */
export function parseJsonLd(blocks) {
  const nodes = [];
  const visit = (n, depth = 0) => {
    if (!n || typeof n !== "object" || depth > 6 || nodes.length > 200) return;
    if (Array.isArray(n)) return n.forEach((x) => visit(x, depth + 1));
    if (n["@graph"]) visit(n["@graph"], depth + 1);
    if (n["@type"]) nodes.push(n);
    for (const [k, v] of Object.entries(n)) if (k !== "@graph" && typeof v === "object") visit(v, depth + 1);
  };
  for (const b of blocks || []) {
    try {
      visit(JSON.parse(b));
    } catch {
      /* invalid JSON-LD is common; skip */
    }
  }
  return nodes;
}

const asList = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
const str = (v) => (typeof v === "string" ? v : v && typeof v === "object" ? v.name || v["@id"] || v.url || "" : String(v ?? ""));

/** Pull identity facts (organisations, people, addresses, contact points, sameAs) out of structured data. */
export function identityFromJsonLd(nodes, bag) {
  const entities = [];
  for (const n of nodes) {
    const types = asList(n["@type"]).map(String);
    const isOrg = types.some((t) => /Organization|Corporation|LocalBusiness|Store|Restaurant|NGO|GovernmentOrganization|EducationalOrganization|NewsMediaOrganization|Brand|Airline|Hotel|MedicalBusiness|ProfessionalService|LegalService/.test(t));
    const isPerson = types.includes("Person");
    if (!isOrg && !isPerson && !types.includes("WebSite") && !types.includes("PostalAddress")) continue;
    const e = { type: types.join(", "), name: str(n.name), legalName: str(n.legalName), url: str(n.url), email: str(n.email).replace(/^mailto:/, ""), telephone: str(n.telephone), sameAs: asList(n.sameAs).map(str).filter(Boolean), address: null, founders: [], ids: {} };
    const addr = n.address && typeof n.address === "object" ? n.address : null;
    if (addr) e.address = squash([addr.streetAddress, addr.postalCode, addr.addressLocality, addr.addressRegion, str(addr.addressCountry)].filter(Boolean).join(", "));
    else if (typeof n.address === "string") e.address = n.address;
    for (const k of ["vatID", "taxID", "duns", "leiCode", "naics", "iso6523Code", "globalLocationNumber"]) if (n[k]) e.ids[k] = str(n[k]);
    for (const f of [...asList(n.founder), ...asList(n.founders), ...asList(n.employee).slice(0, 10)]) if (str(f)) e.founders.push(str(f));
    if (n.geo?.latitude && n.geo?.longitude) bag.add("coordinates", `${Number(n.geo.latitude)}, ${Number(n.geo.longitude)}`, { source: "structured data", extra: { lat: Number(n.geo.latitude), lon: Number(n.geo.longitude) } });
    if (isOrg && e.name) bag.add("organization", e.legalName || e.name, { source: "structured data" });
    if (isPerson && e.name) bag.add("person", e.name, { source: "structured data", confidence: "medium" });
    for (const f of e.founders) bag.add("person", f, { source: "structured data (founder/employee)", confidence: "medium" });
    if (e.email && /@/.test(e.email)) bag.add("email", e.email.toLowerCase(), { source: "structured data" });
    if (e.telephone) bag.add("phone", e.telephone, { source: "structured data" });
    if (e.address) bag.add("address", e.address, { source: "structured data" });
    for (const s of e.sameAs) addUrl(bag, s, { source: "structured data sameAs", addUrl: false });
    for (const v of Object.values(e.ids)) bag.add("business_id", v, { source: "structured data" });
    if (e.name || e.email || e.address || e.sameAs.length) entities.push(e);
  }
  return entities;
}

/** Meta tags -> page facts, verification tokens, social cards. */
export function analyzeMeta(meta, linkTags, bag, pageUrl) {
  const get = (k) => meta.find((m) => m.name === k || m.property === k)?.content || null;
  const verification = [];
  for (const m of meta) {
    const svc = VERIFICATION_META[m.name] || VERIFICATION_META[m.property];
    if (svc) {
      verification.push({ service: svc, name: m.name || m.property, value: m.content });
      bag.add("verification", m.content, { source: "meta tag", label: svc, extra: { service: svc } });
    }
  }
  const og = {}, twitter = {};
  for (const m of meta) {
    if (m.property.startsWith("og:") || m.property.startsWith("article:") || m.property.startsWith("fb:")) og[m.property] = m.content;
    if (m.name.startsWith("twitter:")) twitter[m.name] = m.content;
  }
  for (const k of ["twitter:site", "twitter:creator"]) {
    const v = twitter[k];
    if (v && /^@?[A-Za-z0-9_]{1,15}$/.test(v)) bag.add("social", `https://x.com/${v.replace(/^@/, "")}`, { source: `meta ${k}`, label: "X / Twitter", extra: { handle: v.replace(/^@/, ""), platform: "X / Twitter" } });
  }
  if (og["fb:app_id"]) bag.add("tracker", og["fb:app_id"], { source: "meta fb:app_id", label: "Facebook App ID", extra: { rule: "fb_app", kind: "social", strong: true } });
  if (og["fb:pages"]) bag.add("tracker", og["fb:pages"], { source: "meta fb:pages", label: "Facebook Page ID", extra: { rule: "fb_page", kind: "social", strong: true } });
  if (og["article:author"]) addUrl(bag, og["article:author"], { source: "meta article:author", addUrl: false });

  const relMe = linkTags.filter((l) => /(?:^|\s)me(?:\s|$)/.test(l.rel)).map((l) => l.href);
  for (const h of relMe) addUrl(bag, h, { source: "rel=me", addUrl: false });
  const author = get("author");
  if (author && !/^https?:/.test(author) && author.length < 80) bag.add("person", author, { source: "meta author", confidence: "medium" });
  const alternates = linkTags.filter((l) => l.rel.includes("alternate") && l.hreflang).map((l) => ({ lang: l.hreflang, href: l.href }));
  const preconnect = [...new Set(linkTags.filter((l) => /preconnect|dns-prefetch|preload|prefetch/.test(l.rel)).map((l) => safeUrl(l.href)?.hostname).filter(Boolean))];
  const canonical = linkTags.find((l) => l.rel === "canonical")?.href || null;
  const page = safeUrl(pageUrl);
  return {
    description: get("description") || og["og:description"] || null,
    keywords: get("keywords"),
    author,
    generator: get("generator"),
    robots: get("robots"),
    themeColor: get("theme-color"),
    applicationName: get("application-name") || og["og:site_name"] || null,
    canonical,
    canonicalOffsite: canonical && page ? registrableDomain(safeUrl(canonical)?.hostname || "") !== registrableDomain(page.hostname) : false,
    og,
    twitter,
    verification,
    relMe,
    alternates,
    preconnect,
    manifestUrl: linkTags.find((l) => l.rel === "manifest")?.href || null,
    feeds: linkTags.filter((l) => /rss|atom/.test(l.type)).map((l) => l.href),
    all: meta.slice(0, 300)
  };
}

/**
 * Build the report.
 * @param {object} page     collectPage() output
 * @param {object} [probe]  probeMainWorld() output
 * @param {object} [extra]  { docResponse, robots, sitemap, security, humans, ads, appAds, manifest, scripts:[{url,text}] }
 */
export function buildReport(page, probe = {}, extra = {}) {
  const t0 = Date.now();
  const bag = new IndicatorBag();
  const url = page.url;
  const u = safeUrl(url);
  const host = u?.hostname || "";
  const site = registrableDomain(host);

  if (host) {
    bag.add("domain", site, { source: "page URL", extra: { primary: true } });
    if (host !== site) addHost(bag, host, "page URL");
    else if (/^\d|:/.test(host)) addHost(bag, host, "page URL");
  }

  // --- Text entities -----------------------------------------------------------
  const visible = `${page.title || ""}\n${page.text || ""}\n${page.shadowText || ""}`;
  extractFromText(bag, visible, { source: "page text" });
  // HTML source finds what isn't rendered (hidden elements, attributes) but is noisy: no handles or bare domains.
  const htmlNoScripts = String(page.html || "").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ");
  extractFromText(bag, htmlNoScripts, { source: "page source", domains: false, handles: false, hashes: false, context: false });
  for (const c of page.comments || []) extractFromText(bag, c, { source: "HTML comment", handles: false, hashes: false });

  // --- Links ------------------------------------------------------------------------
  const links = analyzeLinks(page.links || [], url);
  for (const l of links) {
    addUrl(bag, l.url, { source: "link", context: l.text, addUrl: false });
    if (l.host && l.external) bag.add("domain", registrableDomain(l.host), { source: "outbound link", confidence: "medium" });
  }

  // --- Structured data and meta --------------------------------------------------------
  const jsonld = parseJsonLd(page.jsonld);
  const identity = identityFromJsonLd(jsonld, bag);
  const meta = analyzeMeta(page.meta || [], page.linkTags || [], bag, url);

  // --- Resources and third parties ------------------------------------------------------
  const resources = [
    ...(page.resources || []).map((r) => ({ url: r.url, kind: r.kind === "xmlhttprequest" || r.kind === "fetch" ? "xhr" : r.kind === "link" ? "style" : r.kind })),
    ...(page.scripts || []).filter((s) => s.src).map((s) => ({ url: s.src, kind: "script" })),
    ...(page.styles || []).map((s) => ({ url: s, kind: "style" })),
    ...(page.iframes || []).filter((f) => f.src).map((f) => ({ url: f.src, kind: "iframe" })),
    ...(page.images || []).filter((i) => !i.data).map((i) => ({ url: i.src, kind: "img" })),
    ...(page.forms || []).filter((f) => f.action).map((f) => ({ url: f.action, kind: "form" })),
    ...meta.preconnect.map((h) => ({ url: `https://${h}/`, kind: "preconnect" })),
    ...links.filter((l) => l.external).map((l) => ({ url: l.url, kind: "link" }))
  ];
  const tp = thirdParties(resources, url);
  for (const t of tp.filter((t) => t.loaded)) bag.add("domain", t.site, { source: `third-party ${Object.keys(t.kinds).join("/")}`, confidence: "medium", label: t.service || undefined });

  // --- Trackers -------------------------------------------------------------------------------
  const scriptTexts = [
    ...(page.scripts || []).filter((s) => s.text).map((s) => ({ url: null, text: s.text })),
    ...(extra.scripts || []).filter((s) => s.text)
  ];
  const hits = [...findTrackersInText(page.html, "page source")];
  for (const s of extra.scripts || []) hits.push(...findTrackersInText(s.text, `script ${s.url}`));
  for (const r of resources) hits.push(...findTrackersInUrl(r.url, `${r.kind} URL`));
  for (const id of probe.runtimeIds || []) {
    if (id.startsWith("fbpixel:")) hits.push({ rule: "fb_pixel", vendor: "Meta (Facebook) Pixel", kind: "ads", value: id.slice(8), strong: true, source: "runtime" });
    else hits.push(...findTrackersInText(` "${id}" `, "runtime (tag manager)"));
  }
  for (const [k, v] of Object.entries(probe.configs || {})) hits.push(...findTrackersInText(v, `runtime ${k}`));
  if (extra.gtm) for (const g of extra.gtm) hits.push(...findTrackersInText(g.text, `GTM container ${g.id}`));
  const trackers = mergeTrackers(hits);
  for (const t of trackers) {
    const isKey = t.kind === "api key" || t.kind === "payments" || t.kind === "maps" || t.kind === "captcha";
    bag.add(isKey ? "api_key_public" : "tracker", t.value, { source: t.sources.join(", "), label: t.vendor, extra: { rule: t.rule, kind: t.kind, strong: t.strong } });
  }

  // --- Headers, cookies, tech -------------------------------------------------------------------
  const docHeaders = extra.docResponse?.headers || {};
  const headers = extra.docResponse ? analyzeHeaders(docHeaders, url) : null;
  if (headers) for (const h of headers.cspHosts) bag.add("host", h.replace(/^\*\./, ""), { source: "Content-Security-Policy", confidence: "medium" });
  const tech = detectTech({
    html: String(page.html || "").slice(0, 600000),
    urls: resources.map((r) => r.url),
    generator: meta.generator,
    headers: docHeaders,
    cookies: page.cookies || [],
    globals: probe.globals || {}
  });
  for (const t of tech) for (const v of t.vulns) for (const id of v.ids) bag.add("cve", id, { source: `${t.name} ${t.version}`, confidence: "medium" });

  // --- Scripts --------------------------------------------------------------------------------------
  const js = analyzeScripts(scriptTexts, url);
  for (const b of js.buckets) bag.add("bucket", b.name, { source: b.source, label: b.provider });
  for (const h of js.preprodHosts) bag.add("host", h, { source: "JavaScript", label: "Pre-production / internal service", confidence: "medium" });
  const comments = analyzeComments(page.comments);

  // --- Exposures ---------------------------------------------------------------------------------------
  const exposures = [];
  const formValues = (page.forms || []).flatMap((f) => f.fields.filter((x) => x.value).map((x) => `[form field "${x.label || x.name}"] ${x.value}`)).join("\n");
  if (formValues) exposures.push(...scanExposures(formValues, { source: "form field" }));
  exposures.push(...scanExposures(visible, { source: "page text" }));
  exposures.push(...scanExposures(htmlNoScripts, { source: "page source" }).filter((e) => !["iban", "payment_card", "us_ssn", "fi_hetu"].includes(e.id) || !exposures.some((x) => x.value === e.value)));
  for (const s of scriptTexts) exposures.push(...scanExposures(s.text, { source: s.url ? `script ${s.url}` : "inline script" }).filter((e) => !["payment_card", "iban", "us_ssn", "fi_hetu"].includes(e.id)));
  for (const [k, v] of Object.entries(probe.configs || {})) exposures.push(...scanExposures(v, { source: `runtime ${k}` }).filter((e) => !["payment_card", "iban", "us_ssn", "fi_hetu"].includes(e.id)));
  for (const c of page.comments || []) exposures.push(...scanExposures(c, { source: "HTML comment" }));
  for (const l of links) {
    for (const s of l.secrets) {
      exposures.push({ id: "url_credential", label: `Credential in link URL (${s.param})`, severity: "high", value: s.value, masked: s.value.slice(0, 3) + "•••", context: l.url.replace(s.value, "…"), source: "link", extra: { url: l.url } });
    }
  }
  for (const r of page.resources || []) {
    for (const s of urlSecrets(r.url)) {
      // Signed CDN URLs, OAuth codes and analytics session IDs are normal in resource requests.
      if (!/^(?:access_?token|id_?token|refresh_?token|auth_?token|api_?key|apikey|secret|client_?secret|password|passwd|private_?token|jwt)$/i.test(s.param)) continue;
      exposures.push({ id: "url_credential", label: `Credential in resource URL (${s.param})`, severity: "medium", value: s.value, masked: s.value.slice(0, 3) + "•••", context: r.url.slice(0, 200), source: `${r.kind} request`, extra: { url: r.url } });
    }
  }
  for (const f of page.forms || []) {
    for (const h of f.hiddenFields || []) {
      if (/pass|secret|api[_-]?key|token/i.test(h.name) && h.length > 0 && !/csrf|xsrf|authenticity|__requestverification|nonce|captcha|recaptcha/i.test(h.name)) {
        exposures.push({ id: "hidden_field", label: `Secret-looking hidden form field (${h.name})`, severity: "medium", value: h.value, masked: "•••", context: `form ${f.action || ""}`, source: "form", extra: {} });
      }
    }
  }
  // De-duplicate exposures across sources.
  const exSeen = new Set();
  const exposuresUnique = exposures.filter((e) => {
    const k = `${e.id}|${e.value}`;
    if (exSeen.has(k)) return false;
    exSeen.add(k);
    return true;
  }).sort(bySeverity);

  // --- Well-known files ---------------------------------------------------------------------------------
  const wk = {};
  if (extra.robots?.ok) wk.robots = parseRobots(extra.robots.text);
  if (extra.sitemap?.ok && /<(?:urlset|sitemapindex)/i.test(extra.sitemap.text || "")) wk.sitemap = parseSitemap(extra.sitemap.text);
  if (extra.security?.ok && /contact\s*:/i.test(extra.security.text || "")) {
    wk.securityTxt = parseSecurityTxt(extra.security.text);
    for (const c of wk.securityTxt.fields.contact || []) {
      if (!addUrl(bag, c, { source: "security.txt" })) extractFromText(bag, c, { source: "security.txt" });
    }
  }
  if (extra.humans?.ok && !/<html/i.test(extra.humans.text || "")) {
    wk.humansTxt = parseHumans(extra.humans.text);
    extractFromText(bag, wk.humansTxt, { source: "humans.txt" });
  }
  for (const [key, label] of [["ads", "ads.txt"], ["appAds", "app-ads.txt"]]) {
    const r = extra[key];
    if (!r?.ok || /<html/i.test(r.text || "")) continue;
    const parsed = parseAdsTxt(r.text);
    if (!parsed.records) continue;
    wk[key] = parsed;
    for (const d of parsed.direct) {
      if (/google\.com/.test(d.system) && /^pub-\d+$/.test(d.account)) bag.add("tracker", `ca-${d.account}`, { source: `${label} (DIRECT)`, label: "Google AdSense publisher", extra: { rule: "adsense", kind: "ads", strong: true } });
      else bag.add("tracker", d.account, { source: `${label} (DIRECT)`, label: `${d.system} seller account`, extra: { rule: "ads_txt", kind: "ads", strong: true, system: d.system } });
    }
  }
  if (extra.manifest?.ok) {
    wk.manifest = parseManifest(extra.manifest.text);
    for (const a of wk.manifest?.relatedApps || []) if (a.url) addUrl(bag, a.url, { source: "web app manifest" });
  }

  // --- Forms and phishing --------------------------------------------------------------------------------
  const forms = (page.forms || []).map((f) => {
    const action = safeUrl(f.action || url, url);
    return { ...f, actionHost: action?.hostname || "", external: !!action && /^https?:$/.test(action.protocol) && registrableDomain(action.hostname) !== site, insecure: action?.protocol === "http:" };
  });
  const faviconUrl = (page.favicons || [])[0] || null;
  const phishing = phishingScore({ url, title: page.title, text: visible, forms, links, thirdParties: tp, faviconUrl, flags: page.flags, domainAgeDays: extra.domainAgeDays });

  // --- Summary --------------------------------------------------------------------------------------------
  const indicators = bag.list();
  const counts = {};
  for (const i of indicators) counts[i.type] = (counts[i.type] || 0) + 1;
  const strongPivots = indicators.filter((i) => (i.type === "tracker" && i.extra?.strong) || i.type === "verification" || i.type === "api_key_public").length;

  return {
    version: REPORT_VERSION,
    page: {
      url,
      host,
      site,
      unicodeHost: isPunycode(host) ? toUnicode(host) : null,
      title: page.title,
      lang: page.lang,
      charset: page.charset,
      contentType: page.contentType,
      doctype: page.doctype,
      lastModified: page.lastModified,
      referrer: page.referrer,
      htmlLength: page.htmlLength,
      textLength: (page.text || "").length,
      hiddenTextLength: page.hiddenTextLength,
      elementCount: page.elementCount,
      frames: page.frames,
      shadowRoots: page.shadowRoots,
      navigation: page.navigation,
      collectedAt: page.collectedAt,
      favicon: faviconUrl
    },
    meta,
    identity,
    indicators,
    counts,
    strongPivots,
    exposures: exposuresUnique,
    trackers,
    tech,
    headers,
    response: extra.docResponse ? { status: extra.docResponse.status, finalUrl: extra.docResponse.finalUrl, redirected: extra.docResponse.redirected, headers: docHeaders } : null,
    cookies: analyzeCookies(page.cookies),
    storage: page.storage,
    links,
    thirdParties: tp,
    forms,
    phishing,
    wellKnown: wk,
    js,
    comments,
    images: (page.images || []).filter((i) => !i.data).slice(0, 400),
    iframes: page.iframes || [],
    scripts: (page.scripts || []).map((s) => ({ src: s.src, type: s.type, integrity: !!s.integrity, length: s.length || null, external: s.src ? registrableDomain(safeUrl(s.src)?.hostname || "") !== site : false, service: s.src ? classifyHost(safeUrl(s.src)?.hostname || "")?.name || null : null })),
    flags: page.flags || {},
    // Kept for the AI analysis and later re-checks (capped to keep stored reports small).
    content: { text: visible.slice(0, 300000), truncated: visible.length > 300000 },
    timings: { analyzeMs: Date.now() - t0 }
  };
}
