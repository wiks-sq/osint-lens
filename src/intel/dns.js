// DNS over HTTPS (JSON API). Cloudflare first, Google as fallback.
// Passive from the target's point of view: queries go to a public resolver,
// never to the target's own name servers.

import { httpGet } from "./http.js";
import { reverseIPv4, reverseIPv6Nibbles, isIPv4 } from "../core/domain.js";

const RESOLVERS = [
  (name, type) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  (name, type) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`
];

const TYPE_NUM = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, DNSKEY: 48, HTTPS: 65, CAA: 257 };

/** Resolve one record type. Returns an array of answer strings (only answers of the requested type). */
export async function resolve(name, type, o = {}) {
  let lastErr;
  for (const r of RESOLVERS) {
    try {
      const j = await httpGet(r(name, type), { headers: { accept: "application/dns-json" }, timeoutMs: o.timeoutMs ?? 8000, signal: o.signal });
      if (j.Status === 3) return []; // NXDOMAIN
      const want = TYPE_NUM[type];
      return (j.Answer || []).filter((a) => !want || a.type === want).map((a) => cleanData(a.data, type));
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

function cleanData(d, type) {
  let s = String(d);
  if (type === "TXT") {
    // TXT answers are quoted, possibly split into several 255-byte strings.
    const parts = s.match(/"((?:[^"\\]|\\.)*)"/g);
    if (parts) s = parts.map((p) => p.slice(1, -1).replace(/\\"/g, '"')).join("");
  }
  return s.replace(/\.$/, "");
}

/** PTR (reverse DNS) for an IP. */
export async function reverseDns(ip, o = {}) {
  const name = isIPv4(ip) ? `${reverseIPv4(ip)}.in-addr.arpa` : `${reverseIPv6Nibbles(ip)}.ip6.arpa`;
  return resolve(name, "PTR", o).catch(() => []);
}

/**
 * Everything DNS says about a domain, in parallel.
 * @returns {Promise<{A,AAAA,CNAME,NS,MX,TXT,CAA,SOA,dmarc,mtaSts,bimi,errors}>}
 */
export async function dnsProfile(domain, host, o = {}) {
  const errors = [];
  const q = (name, type) => resolve(name, type, o).catch((e) => (errors.push(`${type} ${name}: ${e.message}`), []));
  const target = host || domain;
  const [A, AAAA, CNAME, NS, MX, TXT, CAA, SOA, dmarc, mtaSts, bimi, apexA] = await Promise.all([
    q(target, "A"), q(target, "AAAA"), q(target, "CNAME"), q(domain, "NS"), q(domain, "MX"), q(domain, "TXT"), q(domain, "CAA"), q(domain, "SOA"),
    q(`_dmarc.${domain}`, "TXT"), q(`_mta-sts.${domain}`, "TXT"), q(`default._bimi.${domain}`, "TXT"),
    target !== domain ? q(domain, "A") : Promise.resolve([])
  ]);
  return { target, A, AAAA, CNAME, NS, MX, TXT, CAA, SOA, apexA, dmarc: dmarc.filter((t) => /^v=DMARC1/i.test(t)), mtaSts: mtaSts.filter((t) => /^v=STSv1/i.test(t)), bimi: bimi.filter((t) => /^v=BIMI1/i.test(t)), errors };
}

/** Parse SPF and DMARC into a mail-security summary. */
export function mailSecurity(profile) {
  const spf = (profile.TXT || []).find((t) => /^v=spf1\b/i.test(t)) || null;
  const out = { spf, spfAll: null, spfIncludes: [], spfIps: [], dmarc: profile.dmarc?.[0] || null, dmarcPolicy: null, dmarcReports: [], mtaSts: !!profile.mtaSts?.length, bimi: profile.bimi?.[0] || null, mx: profile.MX || [], providers: [], findings: [] };
  if (spf) {
    for (const term of spf.split(/\s+/).slice(1)) {
      const m = /^([+\-~?]?)(include|redirect|a|mx|ip4|ip6|exists|all)(?:[:=](.+))?$/i.exec(term);
      if (!m) continue;
      const [, qual, mech, val] = m;
      if (/^(include|redirect)$/i.test(mech) && val) out.spfIncludes.push(val);
      if (/^ip[46]$/i.test(mech) && val) out.spfIps.push(val);
      if (/^all$/i.test(mech)) out.spfAll = qual || "+";
    }
    if (out.spfAll === "+" ) out.findings.push({ severity: "high", text: "SPF ends in +all: anyone may send mail as this domain." });
    else if (out.spfAll === "?") out.findings.push({ severity: "medium", text: "SPF ends in ?all (neutral): spoofed mail isn't rejected." });
  } else if ((profile.MX || []).length) out.findings.push({ severity: "medium", text: "No SPF record although the domain receives mail." });
  if (out.dmarc) {
    out.dmarcPolicy = (/;\s*p=([a-z]+)/i.exec(out.dmarc) || [])[1]?.toLowerCase() || null;
    out.dmarcReports = [...out.dmarc.matchAll(/mailto:([^,;\s!]+)/gi)].map((m) => m[1]);
    if (out.dmarcPolicy === "none") out.findings.push({ severity: "low", text: "DMARC policy is p=none (monitoring only): spoofed mail is delivered." });
  } else out.findings.push({ severity: "medium", text: "No DMARC record: the domain can be spoofed in email." });
  const mx = out.mx.join(" ").toLowerCase();
  const providers = [
    [/google\.com|googlemail\.com/, "Google Workspace"], [/outlook\.com|protection\.outlook/, "Microsoft 365"], [/pphosted\.com/, "Proofpoint"],
    [/mimecast/, "Mimecast"], [/zoho/, "Zoho Mail"], [/protonmail|proton\.ch/, "Proton Mail"], [/yandex/, "Yandex Mail"], [/mailgun/, "Mailgun"],
    [/sendgrid/, "SendGrid"], [/amazonses|amazonaws/, "Amazon SES"], [/messagingengine\.com/, "Fastmail"], [/icloud\.com/, "iCloud Mail"], [/barracuda/, "Barracuda"], [/secureserver\.net/, "GoDaddy"], [/ovh/, "OVH"], [/zone\.eu|zonevs/, "Zone"]
  ];
  for (const [re, name] of providers) if (re.test(mx) || out.spfIncludes.some((i) => re.test(i))) out.providers.push(name);
  return out;
}
