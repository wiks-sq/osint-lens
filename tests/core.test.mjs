// Unit tests for the pure analysis modules (src/core). Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { luhn, iban, finnishHetu, finnishBusinessId, usSsn, base58Check, bech32, sha256Sync } from "../src/core/validators.js";
import { registrableDomain, toUnicode, isPunycode, isIPv6, isPrivateIPv4, skeleton, scriptsIn, reverseIPv6Nibbles } from "../src/core/domain.js";
import { IndicatorBag } from "../src/core/indicators.js";
import { extractFromText, addUrl } from "../src/core/entities.js";
import { scanExposures, decodeJwt, urlSecrets } from "../src/core/exposures.js";
import { findTrackersInText, findTrackersInUrl, verificationFromTxt } from "../src/core/trackers.js";
import { detectTech, cmpVersion } from "../src/core/tech.js";
import { analyzeHeaders, cspHosts } from "../src/core/headers.js";
import { analyzeLinks, extOf, classifyHost, thirdParties } from "../src/core/links.js";
import { murmur3, faviconHashes, md5 } from "../src/core/favicon.js";
import { parseImageMetadata } from "../src/core/exif.js";
import { parseDocument, docRows, pdfDate, findPaths, usersFromPaths } from "../src/core/docmeta.js";
import { phishingScore, applyDomainAge } from "../src/core/phishing.js";
import { pivotsFor, expand } from "../src/core/pivots.js";
import { parseRobots, parseSecurityTxt, parseAdsTxt, parseSitemap } from "../src/core/wellknown.js";
import { analyzeScripts, analyzeComments } from "../src/core/jsintel.js";
import { matchSocial } from "../src/core/social.js";
import { buildReport } from "../src/core/analyze.js";
import { toCsv, toMarkdown, toStix } from "../src/core/export.js";
import { mask, entropy } from "../src/core/util.js";

const fixture = (name) => new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
const bagOf = (text, o) => {
  const b = new IndicatorBag();
  extractFromText(b, text, o);
  return b;
};
const values = (bag, type) => bag.ofType(type).map((i) => i.value);

test("checksum validators", () => {
  assert.ok(luhn("4111 1111 1111 1111"));
  assert.ok(!luhn("4111 1111 1111 1112"));
  assert.ok(!luhn("0000000000000000"));
  assert.ok(iban("FI21 1234 5600 0007 85"));
  assert.ok(iban("GB82WEST12345698765432"));
  assert.ok(!iban("GB82WEST12345698765433"));
  assert.ok(finnishHetu("131052-308T"));
  assert.ok(!finnishHetu("131052-308U"));
  assert.ok(finnishBusinessId("0112038-9"));
  assert.ok(!finnishBusinessId("0112038-8"));
  assert.ok(usSsn("078-05-1120"));
  assert.ok(!usSsn("666-12-3456"));
  assert.ok(base58Check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
  assert.ok(!base58Check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"));
  assert.equal(bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "bc");
  assert.equal(bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx"), null);
  const h = [...sha256Sync(new TextEncoder().encode("abc"))].map((b) => b.toString(16).padStart(2, "0")).join("");
  assert.equal(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("domain helpers", () => {
  assert.equal(registrableDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("www.example.com"), "example.com");
  assert.equal(registrableDomain("victim.github.io"), "victim.github.io");
  assert.equal(registrableDomain("1.2.3.4"), "1.2.3.4");
  assert.equal(toUnicode("xn--80ak6aa92e.com"), "аррӏе.com");
  assert.ok(isPunycode("xn--80ak6aa92e.com"));
  assert.equal(skeleton("аррӏе"), "apple");
  assert.deepEqual(scriptsIn("pаypal"), ["Latin", "Cyrillic"]);
  assert.ok(isIPv6("2001:db8::1") && isIPv6("::1") && !isIPv6("12:30:45"));
  assert.ok(isPrivateIPv4("10.1.2.3") && isPrivateIPv4("100.64.0.1") && !isPrivateIPv4("8.8.8.8"));
  assert.equal(reverseIPv6Nibbles("2001:db8::1").slice(0, 8), "1.0.0.0.");
});

test("entity extraction", () => {
  const b = bagOf("Mail jane@acme-corp.fi or info [at] acme [dot] com. Call +358 40 123 4567. BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa, ETH 0x52908400098527886E0F7030069857D2E4169EE7. Server 203.0.113.55 and 10.0.0.1. IPv6 2001:4860:4860::8888. At 60.169857, 24.938379. CVE-2021-44228. IBAN FI2112345600000785. Y-tunnus 0112038-9. Onion duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion. Version 1.2.3.4");
  assert.deepEqual(values(b, "email").sort(), ["info@acme.com", "jane@acme-corp.fi"]);
  assert.deepEqual(values(b, "phone"), ["+358 40 123 4567"]);
  assert.deepEqual(values(b, "crypto").length, 2);
  assert.deepEqual(values(b, "ip").sort(), ["10.0.0.1", "2001:4860:4860::8888", "203.0.113.55"]);
  assert.deepEqual(values(b, "coordinates"), ["60.169857, 24.938379"]);
  assert.deepEqual(values(b, "cve"), ["CVE-2021-44228"]);
  assert.deepEqual(values(b, "iban"), ["FI2112345600000785"]);
  assert.deepEqual(values(b, "business_id"), ["0112038-9"]);
  assert.equal(values(b, "onion").length, 1);
  assert.ok(!values(b, "domain").some((d) => d.endsWith(".onion")));
});

test("entity extraction avoids common false positives", () => {
  const b = bagOf("logo@2x.png, time 12:30:45, version v2.3.4.5, a random 4111 1111 1111 1112 number, @media screen");
  assert.equal(values(b, "email").length, 0);
  assert.equal(values(b, "ip").length, 0);
  assert.equal(values(b, "handle").length, 0);
});

test("URLs imply social profiles, emails, phones and coordinates", () => {
  const b = new IndicatorBag();
  addUrl(b, "mailto:Sales@Example.com?subject=x");
  addUrl(b, "tel:+358401112233");
  addUrl(b, "https://www.google.com/maps/@60.1699,24.9384,15z");
  addUrl(b, "https://www.instagram.com/acme.widgets/");
  assert.deepEqual(values(b, "email"), ["sales@example.com"]);
  assert.deepEqual(values(b, "phone"), ["+358401112233"]);
  assert.deepEqual(values(b, "coordinates"), ["60.1699, 24.9384"]);
  assert.equal(b.ofType("social")[0].label, "Instagram");
});

test("social profile matching", () => {
  assert.equal(matchSocial("https://twitter.com/jack")?.handle, "jack");
  assert.equal(matchSocial("https://twitter.com/share?url=x"), null);
  assert.equal(matchSocial("https://github.com/torvalds/linux")?.handle, "torvalds");
  assert.equal(matchSocial("https://github.com/features"), null);
  assert.equal(matchSocial("https://mastodon.social/@Gargron")?.handle, "@Gargron@mastodon.social");
  assert.equal(matchSocial("https://www.linkedin.com/in/someone/")?.platform, "LinkedIn");
});

test("exposure detectors", () => {
  const found = scanExposures(`AKIAIOSFODNN7EXAMPLE ghp_${"a".repeat(36)} card 4111 1111 1111 1111 password: "hunter2xyz" postgres://admin:s3cret@db:5432/app 131052-308T password="********"`);
  const ids = found.map((f) => f.id);
  for (const id of ["aws_access_key", "github_token", "payment_card", "password_assignment", "db_url", "fi_hetu"]) assert.ok(ids.includes(id), id);
  assert.equal(found.filter((f) => f.id === "password_assignment").length, 1, "placeholder passwords are rejected");
  assert.equal(found.find((f) => f.id === "payment_card").extra.brand, "Visa");
  const jwt = decodeJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJlbWFpbCI6ImFAYi5jb20ifQ.sig");
  assert.equal(jwt.email, "a@b.com");
  assert.deepEqual(urlSecrets("https://x.com/a?token=abcdef123456&q=1").map((s) => s.param), ["token"]);
  assert.equal(mask("4111111111111111"), "4111••••••••1111");
  assert.ok(entropy("aaaa") < entropy("a8Xz!q"));
});

test("tracker IDs and verification tokens", () => {
  const hits = findTrackersInText(`gtag('config', 'G-ABC123XYZ9'); GTM-TEST123 ca-pub-1234567890123456 fbq('init', '123456789012345'); hjid:1234567`);
  const rules = hits.map((h) => h.rule);
  for (const r of ["ga4", "gtm", "adsense", "fb_pixel", "hotjar"]) assert.ok(rules.includes(r), r);
  assert.equal(findTrackersInUrl("https://www.googletagmanager.com/gtag/js?id=G-XYZ7654321")[0].value, "G-XYZ7654321");
  assert.equal(verificationFromTxt("google-site-verification=abc").service, "Google Search Console");
  assert.equal(verificationFromTxt("example-domain-verification=tok123").service, "Example");
  assert.equal(verificationFromTxt("v=spf1 -all"), null);
});

test("technology detection and vulnerable versions", () => {
  const tech = detectTech({ generator: "WordPress 6.2.1", urls: ["https://x/jquery-3.4.1.min.js"], headers: { server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3" }, cookies: ["PHPSESSID"], globals: { React: "18.2.0" } });
  const by = Object.fromEntries(tech.map((t) => [t.name, t]));
  assert.equal(by.WordPress.version, "6.2.1");
  assert.equal(by.jQuery.version, "3.4.1");
  assert.ok(by.jQuery.vulns.length > 0);
  assert.equal(by.Nginx.version, "1.18.0");
  assert.equal(by.React.version, "18.2.0");
  assert.equal(cmpVersion("3.10.0", "3.9.9"), 1);
});

test("header analysis", () => {
  const r = analyzeHeaders({ "Strict-Transport-Security": "max-age=31536000", "content-security-policy": "default-src 'self'; script-src 'self' https://cdn.example.com 'unsafe-inline'", server: "Apache/2.4.41", "x-backend": "10.1.2.3" }, "https://example.com/");
  assert.equal(r.checks.find((c) => c.id === "hsts").status, "pass");
  assert.equal(r.checks.find((c) => c.id === "csp").status, "warn");
  assert.ok(r.leaks.some((l) => l.header === "server" && l.versioned));
  assert.ok(r.leaks.some((l) => /private IP/.test(l.note || "")));
  assert.deepEqual(cspHosts("img-src *.cdn.net data:; connect-src https://api.x.io"), ["*.cdn.net", "api.x.io"]);
});

test("link analysis and third parties", () => {
  const links = analyzeLinks([{ href: "/files/a.PDF" }, { href: "https://other.com/x?api_key=abcdef123456" }, { href: "#top" }, { href: "/.env" }], "https://site.com/page");
  const pdf = links.find((l) => l.ext === "pdf");
  assert.ok(pdf.notable && !pdf.external);
  assert.ok(links.find((l) => l.host === "other.com").secretParams.includes("api_key"));
  assert.equal(links.find((l) => l.ext === "env").category, "config");
  assert.equal(extOf("/a/report.final.xlsx"), "xlsx");
  assert.equal(classifyHost("www.google-analytics.com").name, "Google Analytics");
  const tp = thirdParties([{ url: "https://www.googletagmanager.com/gtm.js", kind: "script" }, { url: "https://site.com/x.js", kind: "script" }], "https://site.com/");
  assert.equal(tp.length, 1);
  assert.equal(tp[0].category, "tag manager");
});

test("favicon hashes match Shodan's", async () => {
  const h = await faviconHashes(fixture("favicon.ico"));
  assert.equal(h.mmh3, 1178126473); // python: mmh3.hash(base64.encodebytes(data))
  assert.equal(murmur3(new TextEncoder().encode("hello")), 613153351);
  assert.equal(md5(new TextEncoder().encode("abc")), "900150983cd24fb0d6963f7d28e17f72");
});

test("image metadata: EXIF with GPS, PNG text", async () => {
  const jpg = await parseImageMetadata(fixture("photo_gps.jpg"));
  assert.equal(jpg.format, "jpeg");
  assert.ok(Math.abs(jpg.gps.lat - 60.169857) < 0.001 && Math.abs(jpg.gps.lon - 24.938379) < 0.001);
  const f = Object.fromEntries(jpg.fields.map((x) => [x.name, x.value]));
  assert.equal(f.Model, "Canon EOS R6");
  assert.equal(f.BodySerialNumber, "032021001234");
  assert.equal(f.Artist, "Jane Example");
  const png = await parseImageMetadata(fixture("meta.png"));
  assert.ok(png.fields.some((x) => x.name === "Author" && x.value === "PNG Author"));
});

test("document metadata: docx and pdf", async () => {
  const docx = await parseDocument(fixture("report.docx"));
  assert.equal(docx.format, "docx");
  assert.equal(docx.fields.Creator, "Matti Meikäläinen");
  assert.equal(docx.fields.Company, "Example Oy");
  assert.deepEqual(docx.users, ["mmeikalainen"]);
  assert.ok(docx.authors.includes("Liisa Virtanen") && docx.authors.includes("Pekka Korhonen"));
  assert.ok(docRows(docx).some((r) => r.group === "Paths"));
  const pdf = await parseDocument(fixture("doc.pdf"));
  assert.equal(pdf.fields.Author, "John Q. Public");
  assert.equal(pdf.fields.Producer, "Microsoft® Word 2019");
  assert.equal(pdfDate("D:20230115093000+02'00'"), "2023-01-15T09:30:00+02:00");
  assert.deepEqual(usersFromPaths(findPaths("saved in C:\\Users\\bob\\Desktop\\x.docx")), ["bob"]);
});

test("phishing heuristics", () => {
  const phish = phishingScore({
    url: "http://paypal-secure-login.example-verify.top/signin",
    title: "PayPal: Log in",
    text: "Your account has been suspended. Verify your account within 24 hours.",
    forms: [{ action: "https://collector.evil.net/post.php", hasPassword: true, hasEmail: true, fields: [] }],
    links: [], thirdParties: []
  });
  assert.equal(phish.level, "high");
  assert.ok(phish.brands.includes("paypal"));
  const legit = phishingScore({ url: "https://www.paypal.com/signin", title: "PayPal", forms: [{ action: "https://www.paypal.com/signin", hasPassword: true, fields: [] }], text: "Forgot password?", links: [], thirdParties: [] });
  assert.equal(legit.level, "minimal");
  const homograph = phishingScore({ url: "https://xn--pypal-4ve.com/", title: "", forms: [{ hasPassword: true, action: "https://xn--pypal-4ve.com/x", fields: [] }], links: [], thirdParties: [] });
  assert.ok(homograph.signals.some((s) => s.id === "punycode"));
  assert.equal(applyDomainAge(legit, 5).signals[0].id, "new_domain");
});

test("pivot links", () => {
  const ip = pivotsFor({ type: "ip", value: "8.8.8.8" });
  assert.ok(ip.some((p) => p.url === "https://www.shodan.io/host/8.8.8.8"));
  const btc = pivotsFor({ type: "crypto", value: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", label: "Bitcoin" });
  assert.ok(btc.some((p) => p.url.includes("mempool.space")));
  const fav = pivotsFor({ type: "favicon", value: "123", extra: { mmh3: 123, md5: "abc" } });
  const fofa = fav.find((p) => p.name === "FOFA").url;
  assert.equal(Buffer.from(decodeURIComponent(fofa.split("qbase64=")[1]), "base64").toString(), 'icon_hash="123"');
  assert.equal(expand("https://x/{q}", { value: "a b" }), "https://x/a%20b");
});

test("well-known files", () => {
  const r = parseRobots("User-agent: *\nDisallow: /admin/\nDisallow: /blog/\nSitemap: https://x/sitemap.xml");
  assert.deepEqual(r.interesting, ["/admin/"]);
  assert.deepEqual(r.sitemaps, ["https://x/sitemap.xml"]);
  const s = parseSecurityTxt("Contact: mailto:sec@x.com\nExpires: 2000-01-01T00:00:00Z");
  assert.ok(s.valid && s.expired);
  const a = parseAdsTxt("google.com, pub-123, DIRECT, f08c47fec0942fa0\n# c\nx.com, 9, RESELLER");
  assert.equal(a.direct[0].account, "pub-123");
  assert.equal(parseSitemap("<urlset><url><loc>https://a/</loc></url></urlset>").count, 1);
});

test("JavaScript intelligence", () => {
  const js = analyzeScripts([{ url: null, text: `fetch("/api/v1/users"); const b = "https://my-bucket.s3.amazonaws.com/x"; const h = "https://grafana.dev.acme.io/"; if (re.test(x)) {} const db = "http://db.corp:5432/"; NEXT_PUBLIC_KEY: "abc"; //# sourceMappingURL=app.js.map` }], "https://acme.io/");
  assert.ok(js.endpoints.some((e) => e.url.endsWith("/api/v1/users")));
  assert.deepEqual(js.buckets.map((b) => b.name), ["my-bucket"]);
  assert.deepEqual(js.preprodHosts, ["grafana.dev.acme.io"]);
  assert.deepEqual(js.internalHosts, ["db.corp:5432"]);
  assert.deepEqual(js.sourcemaps, ["https://acme.io/app.js.map"]);
  assert.ok(analyzeComments(["TODO remove password", "[if IE]"])[0].flagged);
});

test("buildReport end to end on a synthetic page", async () => {
  const page = {
    url: "https://shop.example.com/contact", origin: "https://shop.example.com", title: "Contact", html: `<html><head><meta name="generator" content="WordPress 6.2.1"></head><body>GTM-ABCD12</body></html>`, text: "Email sales@example.com or call +1 415 555 0100.",
    meta: [{ name: "google-site-verification", property: "", httpEquiv: "", content: "tok123" }, { name: "generator", property: "", httpEquiv: "", content: "WordPress 6.2.1" }],
    linkTags: [], links: [{ href: "https://twitter.com/example" }, { href: "/files/price.xlsx", text: "Prices" }],
    scripts: [{ src: null, text: "var k='AKIAIOSFODNN7EXAMPLE';" }], jsonld: ['{"@type":"Organization","name":"Example Inc","sameAs":["https://github.com/example"]}'],
    styles: [], iframes: [], images: [], forms: [], comments: ["TODO: remove"], resources: [], cookies: ["PHPSESSID"], storage: { local: [], session: [] }, flags: {}, favicons: []
  };
  const r = buildReport(page, { globals: {} }, { docResponse: { status: 200, headers: { server: "nginx" } }, robots: { ok: true, text: "Disallow: /admin" } });
  const types = new Set(r.indicators.map((i) => i.type));
  for (const t of ["domain", "email", "phone", "social", "tracker", "verification", "organization"]) assert.ok(types.has(t), t);
  assert.ok(r.exposures.some((e) => e.id === "aws_access_key"));
  assert.ok(r.tech.some((t) => t.name === "WordPress"));
  assert.ok(r.links.some((l) => l.ext === "xlsx" && l.notable));
  assert.equal(r.wellKnown.robots.interesting[0], "/admin");
  r.id = "test";
  r.createdAt = "2026-01-01T00:00:00Z";
  const csv = toCsv(r);
  assert.ok(csv.startsWith("type,value"));
  assert.ok(toMarkdown(r).includes("# OSINT Lens report"));
  const stix = JSON.parse(await toStix(r));
  assert.equal(stix.type, "bundle");
  assert.ok(stix.objects.some((o) => o.type === "email-addr" && o.value === "sales@example.com"));
  assert.ok(stix.objects.some((o) => o.type === "report"));
});

test("CSV export neutralises spreadsheet formulas", () => {
  const csv = toCsv({ page: { url: "u" }, createdAt: "t", indicators: [{ type: "handle", value: "=cmd|' /C calc'!A0", sources: [], confidence: "low", count: 1 }] });
  assert.ok(csv.includes(`"'=cmd`));
});

test("malformed percent-escapes in URLs don't abort the scan", () => {
  // A page linking to "/file%E0.pdf", "mailto:%" or "/profile%" must not throw "URI malformed".
  const links = analyzeLinks([{ href: "https://site.com/report%E0.pdf" }, { href: "mailto:%" }, { href: "tel:%2B358%" }, { href: "https://twitter.com/user%" }], "https://site.com/");
  assert.equal(links.find((l) => /report/.test(l.url)).ext, "pdf");
  const b = new IndicatorBag();
  for (const l of links) addUrl(b, l.url);
  assert.equal(matchSocial("https://twitter.com/jack%"), null);
  assert.equal(extOf("/x/%zz.docx"), "docx");
  const r = buildReport({ url: "https://site.com/a%", origin: "https://site.com", title: "t", html: "", text: "", meta: [], linkTags: [], links: [{ href: "https://site.com/%E0" }, { href: "mailto:%" }], scripts: [], jsonld: [], styles: [], iframes: [], images: [], forms: [], comments: [], resources: [], cookies: [], storage: {}, flags: {}, favicons: [] }, {}, {});
  assert.ok(r.links.length >= 1);
});
