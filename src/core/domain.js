// Domain-name helpers: registrable domain ("eTLD+1"), punycode, IP classes,
// lookalike detection.
//
// Shipping the full Public Suffix List (~250 KB) would bloat the extension, so
// we carry the multi-label public suffixes that matter in practice: country
// second-level domains and the hosting platforms where every customer gets a
// subdomain (on those, "attacker.github.io" and "victim.github.io" are
// different owners, which matters for phishing triage and site grouping).

const MULTI_LABEL_SUFFIXES = new Set(`
co.uk org.uk ac.uk gov.uk ltd.uk plc.uk me.uk net.uk nhs.uk police.uk sch.uk
com.au net.au org.au edu.au gov.au asn.au id.au co.nz org.nz net.nz govt.nz ac.nz
co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr ne.kr go.kr ac.kr
com.br net.br org.br gov.br com.ar com.mx org.mx gob.mx com.co com.pe com.ve com.uy com.ec
com.cn net.cn org.cn gov.cn edu.cn com.hk org.hk com.tw org.tw com.sg org.sg edu.sg gov.sg
com.my com.ph com.vn com.pk com.bd co.id or.id ac.id go.id co.th in.th ac.th co.in net.in org.in gen.in firm.in ac.in gov.in
co.za org.za gov.za ac.za com.ng com.eg com.sa com.tr gov.tr org.tr com.ua org.ua gov.ua com.pl net.pl org.pl
co.il org.il ac.il gov.il com.ru org.ru net.ru spb.ru msk.ru com.es org.es co.at or.at gv.at ac.at
com.gr com.cy com.mt com.pt com.ro co.hu co.ke co.tz co.ug com.gh
github.io gitlab.io githubusercontent.com herokuapp.com vercel.app netlify.app pages.dev workers.dev
web.app firebaseapp.com appspot.com azurewebsites.net azurestaticapps.net cloudapp.net blob.core.windows.net
cloudfront.net s3.amazonaws.com elasticbeanstalk.com amplifyapp.com onrender.com fly.dev railway.app
glitch.me repl.co replit.app surge.sh netlify.com blogspot.com wordpress.com wixsite.com weebly.com
squarespace.com myshopify.com webflow.io carrd.co notion.site framer.app framer.website
ngrok.io ngrok-free.app ngrok.app trycloudflare.com loca.lt serveo.net
000webhostapp.com pythonanywhere.com sites.google.com translate.goog
duckdns.org no-ip.org ddns.net hopto.org zapto.org
`.trim().split(/\s+/));

/** Hosting platforms where anyone can publish under a shared parent domain. */
export const FREE_HOSTING = new Set(
  [...MULTI_LABEL_SUFFIXES].filter((s) => !/^(co|com|org|net|ac|gov|edu|or|ne|go|gen|firm|gob|govt|asn|id|ltd|plc|me|nhs|police|sch|in|spb|msk|gv)\./.test(s))
);

/** Lowercase host without trailing dot or port. */
export function normalizeHost(host) {
  return String(host || "").trim().toLowerCase().replace(/\.$/, "").replace(/:\d+$/, "");
}

/** The registrable domain ("eTLD+1"): "a.b.example.co.uk" -> "example.co.uk". */
export function registrableDomain(host) {
  host = normalizeHost(host);
  if (!host || isIP(host)) return host;
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  for (let n = 3; n >= 2; n--) {
    const suffix = labels.slice(-n).join(".");
    if (MULTI_LABEL_SUFFIXES.has(suffix)) return labels.slice(-(n + 1)).join(".");
  }
  return labels.slice(-2).join(".");
}

/** Public suffix (TLD or multi-label suffix). */
export function publicSuffix(host) {
  const reg = registrableDomain(host);
  return reg.includes(".") ? reg.slice(reg.indexOf(".") + 1) : reg;
}

/** True if `a` and `b` share a registrable domain. */
export const sameSite = (a, b) => registrableDomain(a) === registrableDomain(b);

// --- IP addresses -----------------------------------------------------------

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export const isIPv4 = (s) => IPV4_RE.test(String(s));

export function isIPv6(s) {
  s = String(s).replace(/^\[|\]$/g, "");
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(":")) return false;
  const dbl = s.split("::").length - 1;
  if (dbl > 1) return false;
  const parts = s.split(":").filter((p, i, a) => p !== "" || (i > 0 && i < a.length - 1) || dbl);
  const last = parts[parts.length - 1] || "";
  const groups = last.includes(".") ? (isIPv4(last) ? parts.length + 1 : -1) : parts.length;
  if (groups < 0) return false;
  if (!parts.every((p) => p === "" || p.includes(".") || /^[0-9a-f]{1,4}$/i.test(p))) return false;
  return dbl ? groups <= 8 : groups === 8;
}

export const isIP = (s) => isIPv4(s) || isIPv6(s);

/** Private, loopback, link-local, CGNAT or reserved IPv4. */
export function isPrivateIPv4(ip) {
  if (!isIPv4(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  return (
    a === 10 || a === 127 || a === 0 || a >= 224 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

export function isPrivateIPv6(ip) {
  const s = String(ip).toLowerCase();
  return s === "::1" || s === "::" || /^f[cd]/.test(s) || /^fe[89ab]/.test(s);
}

export const isPublicIP = (ip) => (isIPv4(ip) ? !isPrivateIPv4(ip) : isIPv6(ip) && !isPrivateIPv6(ip));

/** "1.2.3.4" -> "4.3.2.1" (for in-addr.arpa and DNS-based lookups). */
export const reverseIPv4 = (ip) => ip.split(".").reverse().join(".");

/** Expand an IPv6 address and return its nibble-reversed form for ip6.arpa. */
export function reverseIPv6Nibbles(ip) {
  let [head, tail] = String(ip).toLowerCase().split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined && tail ? tail.split(":") : [];
  const fill = tail !== undefined ? Array(8 - h.length - t.length).fill("0") : [];
  const full = [...h, ...fill, ...t].map((g) => g.padStart(4, "0")).join("");
  return full.split("").reverse().join(".");
}

// --- Punycode (RFC 3492), decode only ----------------------------------------

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, numPoints, first) {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function decodeLabel(input) {
  const out = [];
  let i = 0, n = INITIAL_N, bias = INITIAL_BIAS;
  let basic = input.lastIndexOf("-");
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) out.push(input.charCodeAt(j));
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error("bad punycode");
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : BASE;
      if (digit >= BASE) throw new Error("bad punycode");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** "xn--80ak6aa92e.com" -> "аррӏе.com". Invalid labels are left as they are. */
export function toUnicode(host) {
  return normalizeHost(host)
    .split(".")
    .map((l) => {
      if (!l.startsWith("xn--")) return l;
      try {
        return decodeLabel(l.slice(4));
      } catch {
        return l;
      }
    })
    .join(".");
}

export const isPunycode = (host) => /(^|\.)xn--/i.test(String(host));

// --- Lookalikes --------------------------------------------------------------

// Characters that render (nearly) identical to ASCII letters. Not exhaustive;
// it covers the Cyrillic and Greek letters used in real IDN homograph attacks.
const CONFUSABLES = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
  "һ": "h", "ԁ": "d", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ν": "v", "ο": "o", "α": "a", "ε": "e",
  "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ɑ": "a", "ɩ": "i", "ı": "i", "ℓ": "l",
  "０": "0", "１": "1", "ⅼ": "l", "ｍ": "m", "ｎ": "n", "ö": "o", "ó": "o", "ò": "o", "ô": "o", "õ": "o",
  "é": "e", "è": "e", "ê": "e", "ë": "e", "á": "a", "à": "a", "â": "a", "ä": "a", "ã": "a", "å": "a",
  "í": "i", "ì": "i", "î": "i", "ï": "i", "ú": "u", "ù": "u", "û": "u", "ü": "u", "ç": "c", "ñ": "n"
};

/** Reduce a Unicode string to an ASCII "skeleton" for lookalike comparison. */
export function skeleton(s) {
  return Array.from(String(s).normalize("NFKC").toLowerCase(), (ch) => CONFUSABLES[ch] ?? ch)
    .join("")
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w");
}

/** Which Unicode scripts a label mixes (Latin + Cyrillic in one label is a classic homograph). */
export function scriptsIn(label) {
  const scripts = new Set();
  for (const ch of label) {
    if (/[a-z]/i.test(ch)) scripts.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(ch)) scripts.add("Greek");
    else if (/\p{Script=Latin}/u.test(ch)) scripts.add("Latin");
    else if (/\p{L}/u.test(ch)) scripts.add("Other");
  }
  return [...scripts];
}

/** Levenshtein distance, capped for speed. */
export function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}
