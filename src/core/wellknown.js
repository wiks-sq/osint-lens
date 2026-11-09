// Parsers for the public "well-known" files a site publishes about itself:
// robots.txt, sitemap.xml, security.txt (RFC 9116), humans.txt, ads.txt /
// app-ads.txt (IAB) and the web app manifest.
//
// These are conventional, public files that browsers and crawlers request
// routinely. The extension reads them; it never probes for hidden paths.

/** robots.txt -> { disallow, allow, sitemaps, userAgents, interesting } */
export function parseRobots(text) {
  const out = { disallow: [], allow: [], sitemaps: [], userAgents: [], interesting: [] };
  for (const line of String(text || "").split(/\r?\n/)) {
    const m = /^\s*([A-Za-z-]+)\s*:\s*(.*?)\s*(?:#.*)?$/.exec(line);
    if (!m) continue;
    const [, k, v] = m;
    const key = k.toLowerCase();
    if (key === "disallow" && v) out.disallow.push(v);
    else if (key === "allow" && v) out.allow.push(v);
    else if (key === "sitemap" && v) out.sitemaps.push(v);
    else if (key === "user-agent" && v && !out.userAgents.includes(v)) out.userAgents.push(v);
  }
  const INTERESTING = /admin|login|signin|backup|bak|old|dev|staging|test|tmp|private|internal|secret|config|api|graphql|debug|console|dashboard|panel|cgi-bin|phpmyadmin|wp-admin|\.git|\.env|\.sql|dump|export|upload|database|db\b|portal|manage|intranet|beta|v\d+\//i;
  out.interesting = [...new Set([...out.disallow, ...out.allow].filter((p) => INTERESTING.test(p)))];
  out.disallow = [...new Set(out.disallow)];
  out.allow = [...new Set(out.allow)];
  return out;
}

/** sitemap.xml or sitemap index -> { urls, sitemaps, lastmod range } */
export function parseSitemap(xml) {
  const locs = [...String(xml || "").matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1].replace(/&amp;/g, "&"));
  const isIndex = /<sitemapindex/i.test(xml);
  const mods = [...String(xml || "").matchAll(/<lastmod>\s*([^<\s]+)\s*<\/lastmod>/gi)].map((m) => m[1]).sort();
  return {
    isIndex,
    urls: isIndex ? [] : locs,
    sitemaps: isIndex ? locs : [],
    count: locs.length,
    oldest: mods[0] || null,
    newest: mods[mods.length - 1] || null
  };
}

/** security.txt (RFC 9116) -> fields (multi-valued) + expiry check. */
export function parseSecurityTxt(text) {
  const fields = {};
  let signed = false;
  for (const line of String(text || "").split(/\r?\n/)) {
    if (/^-----BEGIN PGP SIGNED MESSAGE-----/.test(line)) signed = true;
    const m = /^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$/.exec(line);
    if (!m || line.trim().startsWith("#")) continue;
    const k = m[1].toLowerCase();
    if (!["contact", "expires", "encryption", "acknowledgments", "preferred-languages", "canonical", "policy", "hiring", "csaf"].includes(k)) continue;
    (fields[k] ||= []).push(m[2]);
  }
  const expires = fields.expires?.[0] ? Date.parse(fields.expires[0]) : NaN;
  return {
    fields,
    signed,
    valid: !!fields.contact?.length,
    expired: Number.isFinite(expires) ? expires < Date.now() : null,
    expires: Number.isFinite(expires) ? new Date(expires).toISOString() : null
  };
}

/** humans.txt is free-form; keep it short and pull out names/handles/emails later via entity extraction. */
export const parseHumans = (text) => String(text || "").slice(0, 4000);

/**
 * ads.txt / app-ads.txt: "<ad system domain>, <publisher account id>, DIRECT|RESELLER, <cert authority id>".
 * DIRECT entries are the site owner's own ad accounts (e.g. "google.com, pub-1234..., DIRECT"):
 * a strong pivot to other sites run by the same publisher.
 */
export function parseAdsTxt(text) {
  const records = [];
  const vars = {};
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const v = /^(contact|subdomain|ownerdomain|managerdomain|inventorypartnerdomain)\s*=\s*(.+)$/i.exec(line);
    if (v) {
      (vars[v[1].toLowerCase()] ||= []).push(v[2].trim());
      continue;
    }
    const parts = line.split(",").map((s) => s.trim());
    if (parts.length < 3) continue;
    records.push({ system: parts[0].toLowerCase(), account: parts[1], relation: parts[2].toUpperCase(), certId: parts[3] || null });
  }
  const direct = records.filter((r) => r.relation === "DIRECT");
  return { records: records.length, direct, resellers: records.length - direct.length, vars };
}

/** Web app manifest -> name, short name, start URL, related apps (store IDs are pivots). */
export function parseManifest(json) {
  let m;
  try {
    m = typeof json === "string" ? JSON.parse(json) : json;
  } catch {
    return null;
  }
  if (!m || typeof m !== "object") return null;
  return {
    name: m.name || null,
    shortName: m.short_name || null,
    startUrl: m.start_url || null,
    scope: m.scope || null,
    gcmSenderId: m.gcm_sender_id || null,
    relatedApps: (m.related_applications || []).map((a) => ({ platform: a.platform, id: a.id || null, url: a.url || null }))
  };
}
