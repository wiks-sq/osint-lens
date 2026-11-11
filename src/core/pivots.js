// Pivot links: one click from an indicator to the services an investigator
// would check next. Nothing is fetched: these are URLs the user chooses to
// open, and the value is only sent to that service when they do.
//
// Placeholders: {q} URL-encoded value, {raw} value as-is, {digits} digits only,
// {lat} {lon} coordinates, {mmh3} {md5} {sha256} favicon hashes, {n} ASN number,
// {b64:...} base64 of the inner template (FOFA queries).

import { safeDecode } from "./util.js";

const G = (q) => ({ name: "Google", url: `https://www.google.com/search?q=${q}` });
const SEARCH = [
  G("%22{q}%22"),
  { name: "Bing", url: "https://www.bing.com/search?q=%22{q}%22" },
  { name: "DuckDuckGo", url: "https://duckduckgo.com/?q=%22{q}%22" }
];
const SOURCE_SEARCH = [
  { name: "PublicWWW (source code search)", url: "https://publicwww.com/websites/%22{q}%22/" },
  { name: "GitHub code search", url: "https://github.com/search?q=%22{q}%22&type=code" }
];

export const PIVOTS = {
  domain: [
    { name: "ICANN RDAP lookup", url: "https://lookup.icann.org/en/lookup?name={q}" },
    { name: "crt.sh (certificates)", url: "https://crt.sh/?q=%25.{q}" },
    { name: "urlscan.io", url: "https://urlscan.io/search/#page.domain%3A{q}" },
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/domain/{q}" },
    { name: "Wayback Machine", url: "https://web.archive.org/web/*/{raw}*" },
    { name: "archive.today", url: "https://archive.ph/{raw}" },
    { name: "SecurityTrails", url: "https://securitytrails.com/domain/{q}/dns" },
    { name: "BuiltWith relationships", url: "https://builtwith.com/relationships/{q}" },
    { name: "DNSlytics", url: "https://dnslytics.com/domain/{q}" },
    { name: "Shodan", url: "https://www.shodan.io/search?query=hostname%3A{q}" },
    { name: "AlienVault OTX", url: "https://otx.alienvault.com/indicator/domain/{q}" },
    { name: "URLhaus", url: "https://urlhaus.abuse.ch/browse.php?search={q}" },
    { name: "Netcraft site report", url: "https://sitereport.netcraft.com/?url=https%3A%2F%2F{q}" },
    { name: "Robtex", url: "https://www.robtex.com/dns-lookup/{q}" },
    { name: "Google Safe Browsing status", url: "https://transparencyreport.google.com/safe-browsing/search?url={q}" },
    G("site%3A{q}")
  ],
  host: [
    { name: "Open https://", url: "https://{raw}/" },
    { name: "crt.sh (exact)", url: "https://crt.sh/?q={q}" },
    { name: "urlscan.io", url: "https://urlscan.io/search/#page.domain%3A{q}" },
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/domain/{q}" },
    { name: "Shodan", url: "https://www.shodan.io/search?query=hostname%3A{q}" },
    { name: "Wayback Machine", url: "https://web.archive.org/web/*/{raw}*" },
    G("site%3A{q}")
  ],
  ip: [
    { name: "Shodan", url: "https://www.shodan.io/host/{q}" },
    { name: "Censys", url: "https://search.censys.io/hosts/{q}" },
    { name: "AbuseIPDB", url: "https://www.abuseipdb.com/check/{q}" },
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/ip-address/{q}" },
    { name: "GreyNoise", url: "https://viz.greynoise.io/ip/{q}" },
    { name: "ipinfo.io", url: "https://ipinfo.io/{q}" },
    { name: "Hurricane Electric BGP", url: "https://bgp.he.net/ip/{q}" },
    { name: "urlscan.io", url: "https://urlscan.io/search/#page.ip%3A%22{q}%22" },
    { name: "Reverse IP (ViewDNS)", url: "https://viewdns.info/reverseip/?host={q}&t=1" },
    { name: "AlienVault OTX", url: "https://otx.alienvault.com/indicator/ip/{q}" },
    { name: "Spur (VPN/proxy context)", url: "https://spur.us/context/{q}" }
  ],
  url: [
    { name: "urlscan.io search", url: "https://urlscan.io/search/#page.url%3A%22{q}%22" },
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/search/{q}" },
    { name: "Wayback Machine", url: "https://web.archive.org/web/*/{raw}" },
    { name: "archive.today", url: "https://archive.ph/newest/{raw}" },
    { name: "Save to Wayback (public!)", url: "https://web.archive.org/save/{raw}" }
  ],
  email: [
    ...SEARCH,
    { name: "GitHub commits", url: "https://github.com/search?q=%22{q}%22&type=commits" },
    { name: "Gravatar avatar", url: "https://gravatar.com/avatar/{md5}?d=404&s=200" },
    { name: "Have I Been Pwned", url: "https://haveibeenpwned.com/" },
    { name: "Intelligence X", url: "https://intelx.io/?s={q}" }
  ],
  phone: [
    ...SEARCH,
    { name: "WhatsApp (wa.me)", url: "https://wa.me/{digits}" }
  ],
  handle: [
    { name: "WhatsMyName", url: "https://whatsmyname.app/?q={handle}" },
    { name: "Google", url: "https://www.google.com/search?q=%22{handle}%22" },
    { name: "GitHub", url: "https://github.com/{handle}" },
    { name: "Keybase", url: "https://keybase.io/{handle}" }
  ],
  social: [
    { name: "Open profile", url: "{raw}" },
    { name: "Wayback Machine", url: "https://web.archive.org/web/*/{raw}" },
    { name: "WhatsMyName (handle)", url: "https://whatsmyname.app/?q={handle}" },
    { name: "Google (handle)", url: "https://www.google.com/search?q=%22{handle}%22" }
  ],
  "crypto:Bitcoin": [
    { name: "mempool.space", url: "https://mempool.space/address/{raw}" },
    { name: "Blockchair", url: "https://blockchair.com/bitcoin/address/{raw}" },
    { name: "WalletExplorer", url: "https://www.walletexplorer.com/address/{raw}" }
  ],
  "crypto:Ethereum / EVM": [
    { name: "Etherscan", url: "https://etherscan.io/address/{raw}" },
    { name: "Blockscan (all EVM chains)", url: "https://blockscan.com/address/{raw}" },
    { name: "DeBank", url: "https://debank.com/profile/{raw}" }
  ],
  "crypto:Litecoin": [{ name: "Blockchair", url: "https://blockchair.com/litecoin/address/{raw}" }],
  "crypto:Dogecoin": [{ name: "Blockchair", url: "https://blockchair.com/dogecoin/address/{raw}" }],
  "crypto:Bitcoin Cash": [{ name: "Blockchair", url: "https://blockchair.com/bitcoin-cash/address/{raw}" }],
  "crypto:Tron": [{ name: "Tronscan", url: "https://tronscan.org/#/address/{raw}" }],
  "crypto:Solana": [{ name: "Solscan", url: "https://solscan.io/account/{raw}" }],
  "crypto:Cardano": [{ name: "Cardanoscan", url: "https://cardanoscan.io/address/{raw}" }],
  crypto: [
    { name: "Chainabuse (scam reports)", url: "https://www.chainabuse.com/address/{raw}" },
    G("%22{q}%22")
  ],
  onion: [{ name: "Ahmia (Tor search)", url: "https://ahmia.fi/search/?q={q}" }, G("%22{q}%22")],
  coordinates: [
    { name: "Google Maps", url: "https://www.google.com/maps/search/?api=1&query={lat},{lon}" },
    { name: "OpenStreetMap", url: "https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}" },
    { name: "Google Earth", url: "https://earth.google.com/web/@{lat},{lon},300a,800d,35y,0h,0t,0r" },
    { name: "Bing Maps", url: "https://www.bing.com/maps?cp={lat}~{lon}&lvl=17&style=h" },
    { name: "Mapillary (street level)", url: "https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=17" },
    { name: "SunCalc (shadows/time)", url: "https://www.suncalc.org/#/{lat},{lon},17/" }
  ],
  tracker: [
    ...SOURCE_SEARCH,
    { name: "DNSlytics reverse analytics", url: "https://dnslytics.com/reverse-analytics/{q}" },
    { name: "SpyOnWeb", url: "https://spyonweb.com/{q}" },
    G("%22{q}%22")
  ],
  "tracker:adsense": [
    { name: "DNSlytics reverse AdSense", url: "https://dnslytics.com/reverse-adsense/{q}" },
    { name: "SpyOnWeb", url: "https://spyonweb.com/{q}" },
    ...SOURCE_SEARCH,
    G("%22{q}%22")
  ],
  "tracker:gtm": [
    { name: "View GTM container (gtm.js)", url: "https://www.googletagmanager.com/gtm.js?id={q}" },
    ...SOURCE_SEARCH,
    G("%22{q}%22")
  ],
  "tracker:ga4": [
    { name: "View gtag config", url: "https://www.googletagmanager.com/gtag/js?id={q}" },
    ...SOURCE_SEARCH,
    G("%22{q}%22")
  ],
  verification: [...SOURCE_SEARCH, G("%22{q}%22")],
  api_key_public: [...SOURCE_SEARCH, G("%22{q}%22")],
  favicon: [
    { name: "Shodan", url: "https://www.shodan.io/search?query=http.favicon.hash%3A{mmh3}" },
    { name: "FOFA", url: "https://en.fofa.info/result?qbase64={b64:icon_hash=\"{mmh3}\"}" },
    { name: "ZoomEye", url: "https://www.zoomeye.ai/searchResult?q=iconhash%3A%22{md5}%22" }
  ],
  asn: [
    { name: "Hurricane Electric BGP", url: "https://bgp.he.net/AS{n}" },
    { name: "ipinfo.io", url: "https://ipinfo.io/AS{n}" },
    { name: "PeeringDB", url: "https://www.peeringdb.com/asn/{n}" },
    { name: "Shodan", url: "https://www.shodan.io/search?query=asn%3AAS{n}" }
  ],
  hash: [
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/search/{q}" },
    { name: "MalwareBazaar", url: "https://bazaar.abuse.ch/browse.php?search={q}" }
  ],
  cve: [
    { name: "NVD", url: "https://nvd.nist.gov/vuln/detail/{q}" },
    { name: "CVE.org", url: "https://www.cve.org/CVERecord?id={q}" },
    { name: "Shodan CVEDB", url: "https://cvedb.shodan.io/cve/{q}" },
    { name: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={q}" }
  ],
  iban: [G("%22{q}%22")],
  business_id: [
    { name: "OpenCorporates", url: "https://opencorporates.com/companies?q={q}" },
    { name: "YTJ (Finnish register)", url: "https://tietopalvelu.ytj.fi/yritys/{q}", when: /^\d{7}-\d$/ },
    G("%22{q}%22")
  ],
  organization: [
    { name: "OpenCorporates", url: "https://opencorporates.com/companies?q={q}" },
    { name: "Wikipedia", url: "https://en.wikipedia.org/w/index.php?search={q}" },
    { name: "LinkedIn companies", url: "https://www.linkedin.com/search/results/companies/?keywords={q}" },
    G("%22{q}%22")
  ],
  person: [G("%22{q}%22"), { name: "LinkedIn", url: "https://www.linkedin.com/search/results/people/?keywords={q}" }],
  address: [
    { name: "Google Maps", url: "https://www.google.com/maps/search/?api=1&query={q}" },
    { name: "OpenStreetMap", url: "https://www.openstreetmap.org/search?query={q}" }
  ],
  bucket: [
    { name: "GrayhatWarfare (public buckets)", url: "https://buckets.grayhatwarfare.com/files?keywords={q}" },
    G("%22{q}%22")
  ]
};

function b64(s) {
  return btoa(unescape(encodeURIComponent(s)));
}

/** Expand a template for an indicator. */
export function expand(template, ind) {
  const value = String(ind.value);
  const extra = ind.extra || {};
  const vars = {
    q: encodeURIComponent(value),
    raw: value,
    digits: value.replace(/\D/g, ""),
    lat: extra.lat ?? value.split(",")[0]?.trim(),
    lon: extra.lon ?? value.split(",")[1]?.trim(),
    mmh3: extra.mmh3 ?? value,
    md5: extra.md5 ?? "",
    sha256: extra.sha256 ?? "",
    n: value.replace(/^AS/i, ""),
    handle: encodeURIComponent(String(extra.handle || value).replace(/^@/, "").split("@")[0])
  };
  return template
    .replace(/\{b64:((?:[^{}]|\{\w+\})*)\}/g, (_, inner) => encodeURIComponent(b64(inner.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? safeDecode(vars[k]) : m)))))
    .replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

/**
 * Pivot links for an indicator.
 * @param {{type:string,value:string,label?:string,extra?:object}} ind
 * @returns {Array<{name:string,url:string}>}
 */
export function pivotsFor(ind) {
  const lists = [];
  if (ind.type === "crypto" && ind.label) lists.push(PIVOTS[`crypto:${ind.label}`]);
  if (ind.type === "tracker" && ind.extra?.rule) lists.push(PIVOTS[`tracker:${ind.extra.rule}`] || PIVOTS.tracker);
  else lists.push(PIVOTS[ind.type]);
  if (ind.type === "crypto") lists.push(PIVOTS.crypto);
  const out = [];
  const seen = new Set();
  for (const l of lists) {
    for (const p of l || []) {
      if (p.when && !p.when.test(ind.value)) continue;
      if (p.url.includes("{md5}") && !ind.extra?.md5) continue;
      const url = expand(p.url, ind);
      if (seen.has(url)) continue;
      seen.add(url);
      out.push({ name: p.name, url });
    }
  }
  return out;
}
