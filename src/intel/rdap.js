// RDAP (the JSON successor of WHOIS) for domains, IP networks and ASNs.
// Domain lookups go straight to the registry using IANA's bootstrap file;
// rdap.org (a public redirector) is the fallback.

import { httpGet } from "./http.js";
import { publicSuffix } from "../core/domain.js";

const ACCEPT = { accept: "application/rdap+json, application/json" };
let bootstrap = null;
let bootstrapAt = 0;

async function dnsBootstrap(o) {
  if (bootstrap && Date.now() - bootstrapAt < 864e5) return bootstrap;
  try {
    const j = await httpGet("https://data.iana.org/rdap/dns.json", { timeoutMs: 10000, signal: o.signal });
    const map = new Map();
    for (const [tlds, urls] of j.services || []) for (const t of tlds) map.set(t.toLowerCase(), urls.find((u) => u.startsWith("https:")) || urls[0]);
    bootstrap = map;
    bootstrapAt = Date.now();
  } catch {
    bootstrap = bootstrap || new Map();
  }
  return bootstrap;
}

/** vCard array -> { name, org, email, phone, address, country } */
export function vcard(arr) {
  const out = {};
  for (const [k, , , v] of (Array.isArray(arr) && arr[1]) || []) {
    const val = Array.isArray(v) ? v.flat().filter(Boolean).join(", ") : v;
    if (!val) continue;
    if (k === "fn") out.name = val;
    else if (k === "org") out.org = val;
    else if (k === "email") out.email = val;
    else if (k === "tel") out.phone = String(val).replace(/^tel:/, "");
    else if (k === "adr") out.address = val;
  }
  return out;
}

/** Flatten nested entities with their roles. */
function entities(obj, depth = 0, out = []) {
  for (const e of obj?.entities || []) {
    const card = vcard(e.vcardArray);
    out.push({ roles: e.roles || [], handle: e.handle || null, ...card, redacted: /redact|privacy|withheld|not disclosed|data protected/i.test(JSON.stringify(card)) });
    if (depth < 3) entities(e, depth + 1, out);
  }
  return out;
}

const event = (obj, action) => (obj.events || []).find((e) => e.eventAction === action)?.eventDate || null;

/** Domain RDAP -> registrar, dates, status, name servers, contacts. */
export async function rdapDomain(domain, o = {}) {
  const tld = publicSuffix(domain).split(".").pop();
  const map = await dnsBootstrap(o);
  const base = map.get(tld);
  const urls = [base && `${base.replace(/\/?$/, "/")}domain/${encodeURIComponent(domain)}`, `https://rdap.org/domain/${encodeURIComponent(domain)}`].filter(Boolean);
  let j, lastErr;
  for (const u of urls) {
    try {
      j = await httpGet(u, { headers: ACCEPT, timeoutMs: o.timeoutMs ?? 15000, signal: o.signal });
      break;
    } catch (e) {
      lastErr = e;
      if (e.status === 404) return { found: false, domain };
    }
  }
  if (!j) throw lastErr;
  const ents = entities(j);
  const registrar = ents.find((e) => e.roles.includes("registrar"));
  const registrant = ents.find((e) => e.roles.includes("registrant"));
  const abuse = ents.find((e) => e.roles.includes("abuse") && e.email);
  const created = event(j, "registration");
  return {
    found: true,
    domain: j.ldhName?.toLowerCase() || domain,
    handle: j.handle || null,
    registrar: registrar ? registrar.name || registrar.org || registrar.handle : null,
    registrarIanaId: (registrar && (j.entities || []).find((e) => (e.roles || []).includes("registrar"))?.publicIds?.find((p) => /IANA/i.test(p.type))?.identifier) || null,
    created,
    updated: event(j, "last changed"),
    expires: event(j, "expiration"),
    ageDays: created ? Math.floor((Date.now() - Date.parse(created)) / 864e5) : null,
    status: j.status || [],
    nameservers: (j.nameservers || []).map((n) => (n.ldhName || "").toLowerCase().replace(/\.$/, "")).filter(Boolean),
    dnssec: j.secureDNS?.delegationSigned ?? null,
    registrant: registrant && !registrant.redacted ? { name: registrant.name, org: registrant.org, email: registrant.email, address: registrant.address } : registrant ? { redacted: true, org: registrant.org || null, country: null } : null,
    abuseEmail: abuse?.email || null,
    contacts: ents.filter((e) => !e.redacted && (e.email || e.org || e.name) && !e.roles.includes("registrar")).slice(0, 10),
    source: j.links?.find((l) => l.rel === "self")?.href || urls[0]
  };
}

/** IP RDAP -> network name, range, country, organisation, abuse contact. */
export async function rdapIp(ip, o = {}) {
  // ARIN's server redirects to whichever regional registry holds the address.
  const opts = { headers: ACCEPT, timeoutMs: o.timeoutMs ?? 15000, signal: o.signal };
  const j = await httpGet(`https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`, opts).catch(() => httpGet(`https://rdap.org/ip/${encodeURIComponent(ip)}`, opts));
  const ents = entities(j);
  const org = ents.find((e) => e.roles.includes("registrant") && (e.org || e.name)) || ents.find((e) => e.org || e.name);
  const abuse = ents.find((e) => e.roles.includes("abuse") && e.email);
  const cidr = (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
  return {
    ip,
    name: j.name || null,
    handle: j.handle || null,
    range: j.startAddress && j.endAddress ? `${j.startAddress} - ${j.endAddress}` : null,
    cidr,
    country: j.country || null,
    type: j.type || null,
    org: org ? org.org || org.name : null,
    abuseEmail: abuse?.email || null,
    registered: event(j, "registration"),
    updated: event(j, "last changed"),
    rir: (j.port43 || "").replace(/^whois\./, "") || null
  };
}
