// Free online OSINT sources. None needs an API key (urlscan.io optionally
// accepts one). Each function returns plain data or throws an Error with a
// readable message.

import { httpGet } from "./http.js";
import { resolve } from "./dns.js";
import { reverseIPv4, reverseIPv6Nibbles, isIPv4 } from "../core/domain.js";
import { extOf, CATEGORIES, NOTABLE_CATEGORIES } from "../core/links.js";

// ---------------------------------------------------------------------------
// Certificate transparency: crt.sh, with Cert Spotter as fallback
// ---------------------------------------------------------------------------

function summariseNames(domain, names, certs) {
  const subs = new Map();
  for (const n of names) {
    const h = n.toLowerCase().replace(/^\*\./, "").trim();
    if (!h || !(h === domain || h.endsWith(`.${domain}`)) || /\s/.test(h)) continue;
    subs.set(h, (subs.get(h) || 0) + 1);
  }
  const wildcard = names.some((n) => n.startsWith("*."));
  const interesting = [...subs.keys()].filter((h) => /(?:^|[.\-])(?:dev|develop|stage|staging|stg|uat|qa|test|beta|demo|sandbox|preprod|admin|vpn|remote|portal|intranet|internal|jenkins|gitlab|git|jira|confluence|grafana|kibana|elastic|api|auth|sso|login|mail|webmail|owa|exchange|autodiscover|backup|old|legacy|db|sql|ftp|sftp|ssh|citrix|rdp)[0-9]*(?:[.\-]|$)/.test(h.slice(0, -domain.length)));
  return { subdomains: [...subs.keys()].sort(), interesting, wildcard, certCount: certs.length, issuers: countIssuers(certs), first: certs.map((c) => c.notBefore).filter(Boolean).sort()[0] || null, last: certs.map((c) => c.notBefore).filter(Boolean).sort().pop() || null };
}

function countIssuers(certs) {
  const m = {};
  for (const c of certs) {
    const k = c.issuer || "unknown";
    m[k] = (m[k] || 0) + 1;
  }
  return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count }));
}

export async function certTransparency(domain, o = {}) {
  try {
    const rows = await httpGet(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&deduplicate=Y`, { timeoutMs: o.timeoutMs ?? 45000, maxBytes: 30e6, retries: 1, signal: o.signal });
    const names = rows.flatMap((r) => String(r.name_value || "").split("\n"));
    const certs = rows.map((r) => ({ issuer: (/O=([^,]+)/.exec(r.issuer_name || "") || [])[1] || r.issuer_name, notBefore: r.not_before }));
    return { source: "crt.sh", ...summariseNames(domain, names, certs) };
  } catch (e) {
    const rows = await httpGet(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`, { timeoutMs: o.timeoutMs ?? 30000, maxBytes: 20e6, signal: o.signal }).catch(() => {
      throw e;
    });
    const names = rows.flatMap((r) => r.dns_names || []);
    const certs = rows.map((r) => ({ issuer: r.issuer?.friendly_name || r.issuer?.name, notBefore: r.not_before }));
    return { source: "Cert Spotter", ...summariseNames(domain, names, certs) };
  }
}

// ---------------------------------------------------------------------------
// Wayback Machine (Internet Archive CDX API)
// ---------------------------------------------------------------------------

const tsDate = (ts) => (ts && ts.length >= 8 ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}` : null);

export async function wayback(host, o = {}) {
  const t = o.timeoutMs ?? 30000;
  const cdx = (q) => `https://web.archive.org/cdx/search/cdx?${q}`;
  const [first, last, urls] = await Promise.all([
    httpGet(cdx(`url=${encodeURIComponent(host)}&output=json&limit=1&fl=timestamp`), { timeoutMs: t, retries: 1, signal: o.signal }).catch(() => null),
    httpGet(cdx(`url=${encodeURIComponent(host)}&output=json&limit=-1&fastLatest=true&fl=timestamp`), { timeoutMs: t, signal: o.signal }).catch(() => null),
    httpGet(cdx(`url=${encodeURIComponent(host)}/*&output=json&fl=timestamp,original,mimetype,statuscode&collapse=urlkey&filter=statuscode:200&limit=2000`), { timeoutMs: t, maxBytes: 15e6, signal: o.signal }).catch(() => null)
  ]);
  if (!first && !last && !urls) throw new Error("Wayback Machine didn't answer");
  const rows = Array.isArray(urls) ? urls.slice(1) : [];
  const files = [];
  const extCount = {};
  for (const [ts, original, mime] of rows) {
    let path;
    try {
      path = new URL(original).pathname;
    } catch {
      continue;
    }
    const ext = extOf(path);
    const cat = Object.entries(CATEGORIES).find(([, list]) => list.includes(ext))?.[0];
    if (ext) extCount[ext] = (extCount[ext] || 0) + 1;
    if (cat && NOTABLE_CATEGORIES.has(cat) && cat !== "executable") files.push({ url: original, archived: `https://web.archive.org/web/${ts}/${original}`, date: tsDate(ts), mime, category: cat, ext });
  }
  return {
    firstSeen: tsDate(first?.[1]?.[0]),
    lastSeen: tsDate(last?.[1]?.[0] || last?.[last?.length - 1]?.[0]),
    urlCount: rows.length,
    capped: rows.length >= 1999,
    topExtensions: Object.entries(extCount).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([ext, count]) => ({ ext, count })),
    files: files.slice(0, 300),
    browse: `https://web.archive.org/web/*/${host}*`
  };
}

// ---------------------------------------------------------------------------
// IP intelligence
// ---------------------------------------------------------------------------

/** Shodan InternetDB: open ports, CPEs, known vulns and tags. Free, no key, weekly-updated. */
export async function internetDb(ip, o = {}) {
  try {
    const j = await httpGet(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { timeoutMs: o.timeoutMs ?? 12000, signal: o.signal });
    return { ports: j.ports || [], hostnames: j.hostnames || [], cpes: j.cpes || [], vulns: j.vulns || [], tags: j.tags || [] };
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

/** Team Cymru IP-to-ASN mapping over DNS (TXT records via DoH). */
export async function asnLookup(ip, o = {}) {
  const name = isIPv4(ip) ? `${reverseIPv4(ip)}.origin.asn.cymru.com` : `${reverseIPv6Nibbles(ip)}.origin6.asn.cymru.com`;
  const [txt] = await resolve(name, "TXT", o);
  if (!txt) return null;
  const [asn, prefix, country, registry, allocated] = txt.split("|").map((s) => s.trim());
  const first = asn.split(" ")[0];
  let asName = null;
  try {
    const [d] = await resolve(`AS${first}.asn.cymru.com`, "TXT", o);
    asName = d ? d.split("|").pop().trim() : null;
  } catch {
    /* name is optional */
  }
  return { asn: Number(first), prefix, country, registry, allocated, name: asName };
}

/** Recognise well-known hosting/CDN networks from the AS name. */
export function hostingOf(asName) {
  const s = String(asName || "").toLowerCase();
  const table = [
    ["cloudflare", "Cloudflare (CDN/proxy: the real origin is hidden)"], ["amazon", "Amazon Web Services"], ["google", "Google Cloud"], ["microsoft", "Microsoft Azure"],
    ["akamai", "Akamai"], ["fastly", "Fastly"], ["digitalocean", "DigitalOcean"], ["hetzner", "Hetzner"], ["ovh", "OVHcloud"], ["linode", "Akamai Linode"],
    ["vultr", "Vultr"], ["choopa", "Vultr"], ["oracle", "Oracle Cloud"], ["alibaba", "Alibaba Cloud"], ["tencent", "Tencent Cloud"], ["github", "GitHub"],
    ["vercel", "Vercel"], ["netlify", "Netlify"], ["automattic", "WordPress.com (Automattic)"], ["squarespace", "Squarespace"], ["wix", "Wix"],
    ["shopify", "Shopify"], ["incapsula", "Imperva"], ["sucuri", "Sucuri"], ["ddos-guard", "DDoS-Guard"], ["stormwall", "StormWall"], ["leaseweb", "Leaseweb"],
    ["contabo", "Contabo"], ["ionos", "IONOS"], ["godaddy", "GoDaddy"], ["namecheap", "Namecheap"], ["hostinger", "Hostinger"], ["upcloud", "UpCloud"], ["scaleway", "Scaleway"]
  ];
  return table.find(([k]) => s.includes(k))?.[1] || null;
}

// ---------------------------------------------------------------------------
// urlscan.io: previous public scans of the domain
// ---------------------------------------------------------------------------

export async function urlscanSearch(domain, o = {}) {
  const headers = o.apiKey ? { "API-Key": o.apiKey } : undefined;
  const j = await httpGet(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`domain:${domain}`)}&size=50`, { headers, timeoutMs: o.timeoutMs ?? 20000, signal: o.signal });
  const results = (j.results || []).map((r) => ({
    time: r.task?.time,
    url: r.page?.url || r.task?.url,
    ip: r.page?.ip,
    asn: r.page?.asn,
    asnname: r.page?.asnname,
    country: r.page?.country,
    server: r.page?.server,
    title: r.page?.title,
    status: r.page?.status,
    result: r.result,
    screenshot: r.screenshot
  }));
  const ips = [...new Set(results.map((r) => r.ip).filter(Boolean))];
  return { total: j.total ?? results.length, results: results.slice(0, 50), ips };
}

// ---------------------------------------------------------------------------
// Google Tag Manager containers: every tag ID configured in the container
// ---------------------------------------------------------------------------

export async function gtmContainer(id, o = {}) {
  const text = await httpGet(`https://www.googletagmanager.com/gtm.js?id=${encodeURIComponent(id)}`, { as: "text", timeoutMs: o.timeoutMs ?? 15000, maxBytes: 4e6, signal: o.signal });
  return { id, text };
}
