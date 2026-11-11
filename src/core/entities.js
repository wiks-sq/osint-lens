// OSINT entity extraction from page text and URLs: emails, phone numbers,
// crypto wallets, IPs, onion services, coordinates, hashes, CVEs, IBANs,
// business IDs and @handles. Checksums are applied wherever a format has one.

import { contextOf, safeUrl, safeDecode } from "./util.js";
import { isIPv4, isIPv6, isPrivateIPv4, isPrivateIPv6, normalizeHost } from "./domain.js";
import { iban, finnishBusinessId, base58Check, bech32 } from "./validators.js";
import { matchSocial } from "./social.js";

// Top-level domains accepted when spotting bare domains in free text. Free text
// is full of "file.js" and "e.g", so only real, common TLDs count there.
// (Domains taken from actual URLs/links don't go through this filter.)
const TEXT_TLDS = new Set(`
com net org edu gov mil int info biz io co ai app dev me tv cc us uk ca au de fr nl be ch at se no dk fi is ie es pt it pl cz sk hu ro bg gr tr ru ua by
lt lv ee jp cn kr in sg hk tw my id th vn ph nz za br ar mx cl pe co ve uy ng ke eg sa ae il ir pk bd lk np
xyz online site store shop tech blog cloud live news club space website email link click top icu vip win bid loan work
agency digital media studio design network solutions systems services company group global world finance money
bank pay crypto exchange games game fun social chat team zone page one
`.trim().split(/\s+/));

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}\b/g;
// "name [at] example [dot] com", "name(at)example.com", "name at example dot com" (bracketed forms only, to avoid prose).
const OBFUSCATED_EMAIL_RE = /\b([A-Za-z0-9._%+\-]{1,64})\s*(?:\[at\]|\(at\)|\{at\}|<at>|\s\[@\]\s|\(@\))\s*((?:[A-Za-z0-9\-]{1,63}(?:\s*(?:\[dot\]|\(dot\)|\{dot\})\s*|\.))+[A-Za-z]{2,24})\b/gi;
const PHONE_INTL_RE = /(?<![\w+/=.])\+[1-9]\d{0,2}[\s.\-]?(?:\(\d{1,4}\)[\s.\-]?)?\d{1,4}(?:[\s.\-]?\d{1,4}){1,5}(?![\w])/g;
// National formats are only trusted when a phone keyword precedes them.
const PHONE_LABELLED_RE = /(?:\b(?:tel|phone|puh|puhelin|mobile|mob|gsm|fax|call|telefon|téléphone|tél|telefono|teléfono)\b\.?:?\s*)(\(?0\d{1,4}\)?[\s.\-]?\d{2,4}(?:[\s.\-]?\d{2,4}){1,3})/gi;
const IPV4_RE = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d|\.\d)/g;
const IPV6_RE = /(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:]|\.[0-9a-f])/gi;
const ONION_RE = /\b[a-z2-7]{56}\.onion\b/gi;
const I2P_RE = /\b[a-z0-9\-]{2,60}\.(?:b32\.)?i2p\b/gi;
const CVE_RE = /\bCVE-(?:19|20)\d{2}-\d{4,7}\b/gi;
const HASH_RE = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
const IBAN_RE = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g;
const FI_BID_RE = /\b\d{7}-\d\b/g;
const VAT_RE = /\b(?:VAT|ALV|USt-?IdNr|TVA|IVA|BTW|MwSt|NIF|CIF|moms)[^A-Za-z0-9]{0,12}([A-Z]{2}[ ]?[0-9A-Z]{8,12})\b/gi;
const HANDLE_RE = /(?<![\w@.\/])@([A-Za-z0-9_]{3,30})(?![\w@.]|\.[a-z])/g;
const DOMAIN_TEXT_RE = /\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b/gi;
const URL_TEXT_RE = /\bhttps?:\/\/[^\s"'<>()\[\]{}]{3,2000}/gi;

// Coordinates: "60.16985, 24.93838" (at least 4 decimals each) and DMS "60°10'11.5"N 24°56'18.2"E".
const COORD_DEC_RE = /(?<![\d.])(-?(?:[1-8]?\d|90)\.\d{4,8})\s*,\s*(-?(?:1[0-7]\d|[1-9]?\d|180)\.\d{4,8})(?!\d|\.\d)/g;
const COORD_DMS_RE = /(\d{1,2})°\s*(\d{1,2})['′]\s*(\d{1,2}(?:\.\d+)?)?["″]?\s*([NS])[\s,]+(\d{1,3})°\s*(\d{1,2})['′]\s*(\d{1,2}(?:\.\d+)?)?["″]?\s*([EW])/g;

// Crypto. Each candidate is checksum-validated before it's reported.
const CRYPTO_RULES = [
  { label: "Bitcoin", re: /\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, check: (s) => (s.startsWith("bc1") ? bech32(s) === "bc" : base58Check(s)) },
  { label: "Ethereum / EVM", re: /\b0x[a-fA-F0-9]{40}\b/g, check: () => true },
  { label: "Litecoin", re: /\b(?:ltc1[ac-hj-np-z02-9]{11,71}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33})\b/g, check: (s) => (s.startsWith("ltc1") ? bech32(s) === "ltc" : base58Check(s)) },
  { label: "Dogecoin", re: /\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b/g, check: base58Check },
  { label: "Tron", re: /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g, check: base58Check },
  { label: "Monero", re: /\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g, check: () => true },
  { label: "Bitcoin Cash", re: /\bbitcoincash:q[a-z0-9]{41}\b/g, check: () => true },
  { label: "Cardano", re: /\baddr1[a-z0-9]{50,110}\b/g, check: (s) => bech32(s) === "addr" },
  { label: "Cosmos", re: /\bcosmos1[a-z0-9]{38}\b/g, check: (s) => bech32(s) === "cosmos" },
  // Solana addresses are plain base58 with no checksum, so they need a nearby keyword.
  { label: "Solana", re: /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g, check: () => true, needsContext: /solana|\bSOL\b|phantom/i }
];

/** Validate a phone candidate: 8-15 digits (E.164), not a date or a long digit run. */
function plausiblePhone(raw) {
  const digits = raw.replace(/\D/g, "");
  if (digits.length < 8 || digits.length > 15) return false;
  if (/^(\d)\1+$/.test(digits)) return false;
  if (/^\+?\d{4}[-./]\d{2}[-./]\d{2}/.test(raw.trim())) return false;
  return true;
}

function cleanEmail(e) {
  return e.replace(/^[._%+\-]+/, "").replace(/\.+$/, "").toLowerCase();
}

const IMAGE_EMAIL = /\.(png|jpe?g|gif|webp|svg|avif)$/i;
const PLACEHOLDER_EMAIL = /^(?:example|test|name|user|email|your(?:name|email)?|someone|john\.?doe|jane\.?doe|foo|bar)@|@(?:example\.(?:com|org|net)|domain\.com|email\.com|test\.com|sentry\.io|sentry-next\.wixpress\.com|wixpress\.com)$/i;

/**
 * Extract indicators from a block of text into `bag`.
 * @param {import("./indicators.js").IndicatorBag} bag
 * @param {string} text
 * @param {object} [o]
 * @param {string} [o.source="text"]
 * @param {boolean} [o.domains=true]   also look for bare domains in the text
 * @param {boolean} [o.handles=true]   also look for @handles
 * @param {boolean} [o.hashes=true]
 * @param {boolean} [o.context=true]   keep surrounding text as context
 */
export function extractFromText(bag, text, o = {}) {
  if (!text) return;
  const source = o.source || "text";
  // Context from markup is noise; only keep it for readable text.
  const ctx = o.context === false ? () => undefined : (m) => contextOf(text, m.index, m[0].length);

  for (const m of text.matchAll(EMAIL_RE)) {
    const e = cleanEmail(m[0]);
    if (IMAGE_EMAIL.test(e) || /^[0-9a-f]{20,}@/.test(e)) continue; // retina images "logo@2x.png", Sentry DSN keys
    bag.add("email", e, { source, context: ctx(m), confidence: PLACEHOLDER_EMAIL.test(e) ? "low" : "high", extra: PLACEHOLDER_EMAIL.test(e) ? { placeholder: true } : undefined });
  }
  for (const m of text.matchAll(OBFUSCATED_EMAIL_RE)) {
    const domain = m[2].replace(/\s*(?:\[dot\]|\(dot\)|\{dot\})\s*/gi, ".").replace(/\s+/g, "");
    bag.add("email", cleanEmail(`${m[1]}@${domain}`), { source, context: ctx(m), label: "Obfuscated", extra: { obfuscated: true } });
  }

  for (const m of text.matchAll(PHONE_INTL_RE)) {
    if (plausiblePhone(m[0])) bag.add("phone", m[0].trim().replace(/\s+/g, " "), { source, context: ctx(m) });
  }
  for (const m of text.matchAll(PHONE_LABELLED_RE)) {
    if (plausiblePhone(m[1])) bag.add("phone", m[1].trim().replace(/\s+/g, " "), { source, context: ctx(m), confidence: "medium", label: "National format" });
  }

  for (const m of text.matchAll(IPV4_RE)) {
    const ip = m[0];
    // Version strings ("1.2.3.4" right after "v" or "version") are not addresses.
    const before = text.slice(Math.max(0, m.index - 12), m.index);
    if (/\b(?:v|ver|version|build|release)[\s:]*$/i.test(before)) continue;
    bag.add("ip", ip, { source, context: ctx(m), label: isPrivateIPv4(ip) ? "Private / reserved" : "Public IPv4", confidence: isPrivateIPv4(ip) ? "medium" : "high", extra: { private: isPrivateIPv4(ip) } });
  }
  for (const m of text.matchAll(IPV6_RE)) {
    const ip = m[0];
    if (!isIPv6(ip) || /^[0-9]+:[0-9]+$/.test(ip) || ip.split(":").length < 4) continue; // times like 12:30:45
    bag.add("ip", ip.toLowerCase(), { source, context: ctx(m), label: isPrivateIPv6(ip) ? "Private / reserved" : "Public IPv6", extra: { private: isPrivateIPv6(ip) } });
  }

  for (const m of text.matchAll(ONION_RE)) bag.add("onion", m[0].toLowerCase(), { source, context: ctx(m), label: "Tor v3" });
  for (const m of text.matchAll(I2P_RE)) bag.add("onion", m[0].toLowerCase(), { source, context: ctx(m), label: "I2P" });
  for (const m of text.matchAll(CVE_RE)) bag.add("cve", m[0].toUpperCase(), { source, context: ctx(m) });

  if (o.hashes !== false) {
    for (const m of text.matchAll(HASH_RE)) {
      const h = m[0];
      if (!/[a-f]/i.test(h) || !/\d/.test(h)) continue;
      const label = h.length === 64 ? "SHA-256" : h.length === 40 ? "SHA-1" : "MD5";
      bag.add("hash", h.toLowerCase(), { source, context: ctx(m), label, confidence: "low" });
    }
  }

  for (const m of text.matchAll(IBAN_RE)) {
    if (iban(m[0])) bag.add("iban", m[0].replace(/\s+/g, ""), { source, context: ctx(m) });
  }
  for (const m of text.matchAll(FI_BID_RE)) {
    if (finnishBusinessId(m[0])) bag.add("business_id", m[0], { source, context: ctx(m), label: "Finnish Business ID (Y-tunnus)", confidence: "medium" });
  }
  for (const m of text.matchAll(VAT_RE)) {
    bag.add("business_id", m[1].replace(/\s+/g, "").toUpperCase(), { source, context: ctx(m), label: "VAT number", confidence: "medium" });
  }

  for (const rule of CRYPTO_RULES) {
    for (const m of text.matchAll(rule.re)) {
      const v = m[0];
      if (rule.needsContext && !rule.needsContext.test(text.slice(Math.max(0, m.index - 60), m.index + v.length + 60))) continue;
      // Long base58/hex runs inside URLs/paths are usually IDs, not wallets.
      if (/[\/=?&]$/.test(text[m.index - 1] || "")) continue;
      if (!rule.check(v)) continue;
      bag.add("crypto", v, { source, context: ctx(m), label: rule.label });
    }
  }

  for (const m of text.matchAll(COORD_DEC_RE)) {
    const lat = Number(m[1]), lon = Number(m[2]);
    if (Math.abs(lat) < 0.01 && Math.abs(lon) < 0.01) continue;
    bag.add("coordinates", `${lat}, ${lon}`, { source, context: ctx(m), confidence: "medium", extra: { lat, lon } });
  }
  for (const m of text.matchAll(COORD_DMS_RE)) {
    const toDec = (d, mi, s, h) => (Number(d) + Number(mi) / 60 + Number(s || 0) / 3600) * (/[SW]/.test(h) ? -1 : 1);
    const lat = +toDec(m[1], m[2], m[3], m[4]).toFixed(6);
    const lon = +toDec(m[5], m[6], m[7], m[8]).toFixed(6);
    bag.add("coordinates", `${lat}, ${lon}`, { source, context: ctx(m), extra: { lat, lon, dms: m[0] } });
  }

  if (o.handles !== false) {
    for (const m of text.matchAll(HANDLE_RE)) {
      if (/^\d+$/.test(m[1]) || /^(media|import|font-face|keyframes|charset|supports|layer|container|property|page|namespace|context|type|id|graph|vocab|base|version|param|returns?|deprecated|example|license|todo)$/i.test(m[1])) continue;
      bag.add("handle", `@${m[1]}`, { source, context: ctx(m), confidence: "low" });
    }
  }

  for (const m of text.matchAll(URL_TEXT_RE)) {
    const url = m[0].replace(/[.,;:!?'")\]]+$/, "");
    addUrl(bag, url, { source, context: ctx(m) });
  }

  if (o.domains !== false) {
    for (const m of text.matchAll(DOMAIN_TEXT_RE)) {
      const d = m[0].toLowerCase();
      if (!TEXT_TLDS.has(m[1].toLowerCase()) || d.split(".").length < 2) continue;
      const prev = text[m.index - 1] || "";
      if (prev === "@" || prev === "/" || prev === "." || /^\d+(\.\d+)+$/.test(d)) continue;
      if (/\.(js|css|png|jpg|php|html?)$/i.test(d)) continue;
      bag.add("domain", d.replace(/^www\./, ""), { source, context: ctx(m), confidence: "medium" });
    }
  }
}

/**
 * Add a URL and what it implies: social profile, mailto/tel targets, map coordinates.
 * Returns the parsed URL or null.
 */
export function addUrl(bag, href, o = {}) {
  const u = safeUrl(href);
  if (!u) return null;
  const source = o.source || "link";
  if (u.protocol === "mailto:") {
    const addr = safeDecode(u.pathname).split(/[,;]/)[0].trim();
    if (/@/.test(addr)) bag.add("email", cleanEmail(addr), { source: "mailto link", context: o.context });
    return u;
  }
  if (u.protocol === "tel:" || u.protocol === "sms:") {
    const num = safeDecode(u.pathname).replace(/[^\d+()\-\s.]/g, "").trim();
    if (num.replace(/\D/g, "").length >= 6) bag.add("phone", num, { source: "tel link", context: o.context });
    return u;
  }
  if (/^(bitcoin|ethereum|litecoin|monero|dogecoin):$/.test(u.protocol)) {
    const addr = u.pathname.replace(/^\/\//, "");
    if (addr) bag.add("crypto", addr, { source: "payment link", label: u.protocol.slice(0, -1).replace(/^./, (c) => c.toUpperCase()) });
    return u;
  }
  if (!/^https?:$/.test(u.protocol)) return u;

  const social = matchSocial(u.href);
  if (social) bag.add("social", social.url, { source, label: social.platform, extra: { handle: social.handle, platform: social.platform } });

  // Coordinates encoded in map links.
  const host = u.hostname;
  let lat, lon;
  const at = /@(-?\d{1,2}\.\d{3,}),(-?\d{1,3}\.\d{3,})/.exec(u.pathname);
  const q = u.searchParams.get("q") || u.searchParams.get("ll") || u.searchParams.get("query") || u.searchParams.get("center") || "";
  const qm = /^(-?\d{1,2}\.\d{3,}),\s*(-?\d{1,3}\.\d{3,})$/.exec(q);
  const osm = /map=\d+\/(-?\d{1,2}\.\d+)\/(-?\d{1,3}\.\d+)/.exec(u.hash);
  if (/google\.|maps\.apple\.com|openstreetmap\.org|bing\.com|waze\.com/.test(host)) {
    if (at) [lat, lon] = [at[1], at[2]];
    else if (qm) [lat, lon] = [qm[1], qm[2]];
    else if (osm) [lat, lon] = [osm[1], osm[2]];
    if (lat !== undefined) bag.add("coordinates", `${Number(lat)}, ${Number(lon)}`, { source: "map link", extra: { lat: Number(lat), lon: Number(lon) } });
  }

  if (/\.onion$/.test(host)) bag.add("onion", host, { source, label: "Tor" });
  if (o.addUrl !== false) bag.add("url", u.href.replace(/#.*$/, ""), { source, context: o.context, confidence: "medium" });
  return u;
}

/** Add a hostname (and its IP-ness) from a URL or resource. */
export function addHost(bag, host, source) {
  host = normalizeHost(host);
  if (!host) return;
  if (isIPv4(host) || isIPv6(host)) {
    const priv = isIPv4(host) ? isPrivateIPv4(host) : isPrivateIPv6(host);
    bag.add("ip", host, { source, label: priv ? "Private / reserved" : "Public IP", extra: { private: priv } });
    return;
  }
  bag.add("host", host, { source });
}
