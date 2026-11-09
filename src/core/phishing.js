// Phishing and scam triage. Each signal is explained and weighted; the score
// is a triage aid, not a verdict. A young legitimate startup can trip "new
// domain"; a phishing page on a compromised old site won't. Read the signals.

import { registrableDomain, publicSuffix, isPunycode, toUnicode, skeleton, scriptsIn, editDistance, isIP, FREE_HOSTING } from "./domain.js";

/** Frequently impersonated brands and the registrable domains they really use. */
export const BRANDS = {
  paypal: ["paypal.com", "paypal.me", "paypalobjects.com"],
  apple: ["apple.com", "icloud.com", "apple.news", "me.com"],
  icloud: ["icloud.com", "apple.com"],
  microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "azure.com", "windows.net", "sharepoint.com", "bing.com", "msn.com", "microsoft365.com", "skype.com", "xbox.com", "office365.com"],
  office365: ["office.com", "microsoft.com", "microsoftonline.com", "office365.com"],
  outlook: ["outlook.com", "live.com", "microsoft.com", "office.com"],
  onedrive: ["live.com", "microsoft.com", "onedrive.com", "sharepoint.com"],
  sharepoint: ["sharepoint.com", "microsoft.com"],
  google: ["google.com", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "goo.gl", "g.co", "withgoogle.com", "google.dev"],
  gmail: ["gmail.com", "google.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amazon.ca", "amazon.com.au", "amazon.in", "amazon.nl", "amazon.se", "amazon.pl", "amazonaws.com", "aws.amazon.com", "a2z.com", "media-amazon.com"],
  facebook: ["facebook.com", "fb.com", "fbcdn.net", "meta.com", "messenger.com"],
  instagram: ["instagram.com", "cdninstagram.com", "meta.com"],
  whatsapp: ["whatsapp.com", "whatsapp.net", "wa.me", "meta.com"],
  netflix: ["netflix.com", "nflxext.com", "nflximg.net"],
  linkedin: ["linkedin.com", "licdn.com"],
  dropbox: ["dropbox.com", "dropboxusercontent.com", "db.tt"],
  docusign: ["docusign.com", "docusign.net"],
  adobe: ["adobe.com", "adobelogin.com", "acrobat.com", "typekit.net"],
  dhl: ["dhl.com", "dhl.de", "dhl.fi", "dhl.co.uk", "dhlparcel.nl"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  usps: ["usps.com"],
  posti: ["posti.fi", "posti.com"],
  royalmail: ["royalmail.com"],
  chase: ["chase.com", "jpmorganchase.com", "jpmorgan.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com", "bofa.com"],
  citibank: ["citi.com", "citibank.com"],
  hsbc: ["hsbc.com", "hsbc.co.uk"],
  barclays: ["barclays.co.uk", "barclays.com"],
  santander: ["santander.com", "santander.co.uk"],
  nordea: ["nordea.fi", "nordea.com", "nordea.se", "nordea.dk", "nordea.no"],
  osuuspankki: ["op.fi"],
  danskebank: ["danskebank.fi", "danskebank.com", "danskebank.dk", "danskebank.se"],
  revolut: ["revolut.com"],
  wise: ["wise.com"],
  coinbase: ["coinbase.com"],
  binance: ["binance.com"],
  kraken: ["kraken.com"],
  metamask: ["metamask.io"],
  ledger: ["ledger.com"],
  trezor: ["trezor.io"],
  opensea: ["opensea.io"],
  uniswap: ["uniswap.org", "app.uniswap.org"],
  steam: ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
  roblox: ["roblox.com"],
  epicgames: ["epicgames.com"],
  discord: ["discord.com", "discord.gg", "discordapp.com", "discord.media"],
  telegram: ["telegram.org", "t.me", "telegram.me"],
  twitter: ["twitter.com", "x.com", "twimg.com", "t.co"],
  tiktok: ["tiktok.com", "tiktokcdn.com"],
  yahoo: ["yahoo.com", "yahoo.co.jp", "yimg.com"],
  aol: ["aol.com"],
  spotify: ["spotify.com", "scdn.co"],
  ebay: ["ebay.com", "ebay.co.uk", "ebay.de", "ebaystatic.com"],
  walmart: ["walmart.com"],
  alibaba: ["alibaba.com", "aliexpress.com", "alicdn.com"],
  irs: ["irs.gov"],
  hmrc: ["gov.uk"],
  vero: ["vero.fi"],
  kela: ["kela.fi"],
  suomi: ["suomi.fi"],
  github: ["github.com", "githubusercontent.com", "github.io"],
  zoom: ["zoom.us", "zoom.com"],
  webex: ["webex.com", "cisco.com"],
  okta: ["okta.com", "oktacdn.com"],
  salesforce: ["salesforce.com", "force.com", "my.salesforce.com"],
  stripe: ["stripe.com"],
  booking: ["booking.com"],
  airbnb: ["airbnb.com"],
  mastercard: ["mastercard.com"],
  visa: ["visa.com"],
  americanexpress: ["americanexpress.com", "aexp.com"],
  wetransfer: ["wetransfer.com", "we.tl"],
  mygov: ["my.gov.au", "gov.au"]
};

const SUSPICIOUS_TLDS = new Set(["zip", "mov", "top", "xyz", "icu", "click", "link", "work", "live", "rest", "cyou", "cfd", "sbs", "quest", "buzz", "monster", "gq", "ml", "cf", "ga", "tk", "pw", "cn", "ru", "su", "vip", "bond", "lol", "mom", "beauty", "hair", "skin", "boats", "autos", "makeup", "support", "help", "online", "site", "website", "space", "fun", "shop", "store", "loan", "win", "bid", "review", "country", "kim", "date", "party", "science", "trade", "accountant", "download", "racing", "stream", "gdn", "men", "life"]);

const URGENCY_RE = /\b(?:verify your (?:account|identity)|account (?:has been |was |will be )?(?:suspended|locked|limited|disabled|restricted)|unusual (?:sign[- ]?in|activity)|confirm your (?:identity|account|payment|details)|update your (?:payment|billing|account)|within 24 hours|immediately|final (?:notice|warning)|security alert|your package (?:could not|couldn't) be delivered|delivery (?:failed|attempt)|pay (?:the )?(?:customs|shipping) fee|claim your (?:reward|prize|airdrop|refund)|you have won|wallet (?:validation|synchroni[sz]ation)|connect (?:your )?wallet|seed phrase|recovery phrase|secret phrase|private key|tax refund|refund (?:is )?pending)\b/gi;
const SEED_RE = /\b(?:12|24)[- ](?:word|words)\b|\b(?:seed|recovery|mnemonic|secret) phrase\b/i;

/**
 * @param {object} p
 * @param {string} p.url
 * @param {string} [p.title]
 * @param {string} [p.text]             visible text
 * @param {Array}  [p.forms]            collector forms
 * @param {Array}  [p.links]            analyzeLinks output
 * @param {Array}  [p.thirdParties]     thirdParties output
 * @param {string} [p.faviconUrl]
 * @param {number} [p.domainAgeDays]    from RDAP, when available
 * @param {object} [p.flags]            collector flags (rightClickBlocked, devtoolsDetect, obfuscated, metaRefresh, fullPageIframe...)
 * @param {string[]} [p.scriptHosts]
 */
export function phishingScore(p) {
  const signals = [];
  const add = (id, weight, title, detail) => signals.push({ id, weight, title, detail });
  let u;
  try {
    u = new URL(p.url);
  } catch {
    return { score: 0, level: "unknown", signals: [] };
  }
  const host = u.hostname.toLowerCase();
  const site = registrableDomain(host);
  const tld = publicSuffix(host);
  const sld = site.split(".")[0];
  const unicodeHost = toUnicode(host);
  const text = String(p.text || "").slice(0, 200000);
  const title = String(p.title || "");
  const forms = p.forms || [];
  const pwForms = forms.filter((f) => f.hasPassword);
  const cardForms = forms.filter((f) => f.hasCard);

  // --- The URL itself ------------------------------------------------------
  if (isIP(host)) add("ip_host", 20, "Host is a bare IP address", "Legitimate services almost never ask you to log in on a raw IP.");
  if (u.protocol === "http:" && (pwForms.length || cardForms.length)) add("http_credentials", 25, "Credentials requested over plain HTTP", "The form would send passwords or card numbers unencrypted.");
  if (isPunycode(host)) {
    const mixed = unicodeHost.split(".").some((l) => scriptsIn(l).length > 1);
    add("punycode", mixed ? 30 : 12, mixed ? "Internationalised domain mixing scripts (homograph)" : "Internationalised (punycode) domain", `Displayed as "${unicodeHost}".`);
  }
  if (FREE_HOSTING.has(publicSuffix(host)) || FREE_HOSTING.has(tld)) add("free_hosting", 10, "Hosted on a free/shared hosting or tunnelling service", `Anyone can publish under ${tld}.`);
  if (SUSPICIOUS_TLDS.has(tld.split(".").pop())) add("tld", 6, `Top-level domain .${tld.split(".").pop()} is heavily abused`, "Cheap TLDs dominate phishing registrations; not proof on its own.");
  const labels = host.split(".");
  if (labels.length >= 5) add("deep_subdomain", 8, "Unusually deep subdomain", host);
  if ((sld.match(/-/g) || []).length >= 3) add("hyphens", 6, "Many hyphens in the domain", site);
  if (host.length > 50) add("long_host", 5, "Very long hostname", `${host.length} characters`);
  if (/@/.test(p.url.split("?")[0].replace(/^https?:\/\//, ""))) add("at_in_url", 15, "URL contains @ (user-info trick)", "Everything before @ is ignored by the browser.");
  if (/(?:login|signin|sign-in|verify|account|secure|update|webscr|banking|wallet|auth|recover|unlock|support)[\w\-]*\.(?:[a-z0-9\-]+\.)+/i.test(host) && labels.length > 2) add("keyword_subdomain", 8, "Security/login keyword in the subdomain", host);

  // --- Brand impersonation ---------------------------------------------------
  const skel = skeleton(unicodeHost);
  const hostWords = skel.split(/[.\-]/);
  const titleLow = title.toLowerCase();
  const brandsSeen = [];
  for (const [brand, domains] of Object.entries(BRANDS)) {
    const legit = domains.some((d) => site === d || host === d || host.endsWith(`.${d}`) || site === registrableDomain(d));
    if (legit) continue;
    const inHost = hostWords.some((w) => w === brand || (w.length > 4 && w.includes(brand))) || skel.replace(/[.\-]/g, "").includes(brand);
    const typo = !inHost && brand.length >= 5 && hostWords.some((w) => w.length >= 5 && w !== brand && editDistance(w, brand, 2) <= (brand.length >= 8 ? 2 : 1));
    const inTitle = new RegExp(`\\b${brand}\\b`, "i").test(titleLow);
    if (inHost) brandsSeen.push(brand), add(`brand_host:${brand}`, 25, `Brand "${brand}" in a domain it doesn't own`, `${brand} uses ${domains.slice(0, 3).join(", ")}.`);
    else if (typo) brandsSeen.push(brand), add(`brand_typo:${brand}`, 25, `Domain looks like a misspelling of "${brand}"`, `${host} vs ${domains[0]}`);
    else if (inTitle && (pwForms.length || cardForms.length)) brandsSeen.push(brand), add(`brand_title:${brand}`, 20, `Page claims to be ${brand} but isn't on ${brand}'s domain`, `Title: "${title.slice(0, 80)}"`);
  }

  // --- Forms ------------------------------------------------------------------
  for (const f of forms) {
    let action;
    try {
      action = new URL(f.action || p.url, p.url);
    } catch {
      continue;
    }
    if (!(f.hasPassword || f.hasCard || f.hasEmail)) continue;
    const what = f.hasPassword ? "password" : f.hasCard ? "card" : "email";
    if (/^https?:$/.test(action.protocol) && registrableDomain(action.hostname) !== site) {
      add("form_external", 20, `${what} form submits to another site`, `Posts to ${action.hostname}`);
    }
    if (/api\.telegram\.org|discord(?:app)?\.com\/api\/webhooks|formspree\.io|getform\.io|formsubmit\.co|ngrok|webhook\.site|requestbin|pipedream\.net/i.test(action.href)) {
      add("form_exfil", 30, `${what} form sends data to a messaging/webhook service`, action.hostname);
    }
    if (/^(?:data|blob|javascript):/i.test(f.action || "")) add("form_scheme", 15, "Form action uses a data:/blob:/javascript: URL", String(f.action).slice(0, 60));
    if (/\.php(?:$|\?)/i.test(action.pathname) && f.hasPassword && /(?:next|mail|post|send|login|log|go|submit|verify|process)\d*\.php$/i.test(action.pathname)) add("php_mailer", 8, "Password form posts to a generic PHP handler", action.pathname);
  }
  if (pwForms.length && !text.match(/forgot|reset|lost|unohtu|vergessen|oublié/i)) add("no_recovery", 4, "Login form without any password-recovery link", "Real login pages almost always offer one.");
  if (cardForms.length && pwForms.length) add("card_and_password", 10, "Asks for both a password and card details", "Uncommon outside of account sign-up flows.");

  // --- Content -------------------------------------------------------------------
  const urgency = [...new Set((text.match(URGENCY_RE) || []).map((s) => s.toLowerCase()))];
  if (urgency.length >= 2) add("urgency", Math.min(15, urgency.length * 4), "Urgent or threatening language", urgency.slice(0, 4).join("; "));
  else if (urgency.length) add("urgency", 4, "Urgent or threatening language", urgency[0]);
  if (SEED_RE.test(text) && forms.some((f) => f.textareas > 0 || f.inputs >= 12)) add("seed_phrase", 35, "Asks for a wallet recovery (seed) phrase", "No legitimate service ever asks for this.");
  const links = p.links || [];
  const placeholder = links.filter((l) => /#$|javascript:void/i.test(l.url)).length;
  const internal = links.filter((l) => !l.external && /^https?:/.test(l.url));
  if (pwForms.length && links.length >= 5 && internal.length / links.length < 0.2) add("links_offsite", 10, "Most links point to another site", "Phishing kits often copy the real site's navigation links verbatim.");
  if (placeholder > 15) add("dead_links", 4, "Many placeholder links (#)", `${placeholder} links go nowhere`);

  // --- Resources ----------------------------------------------------------------
  if (p.faviconUrl) {
    try {
      const fav = new URL(p.faviconUrl, p.url);
      const favSite = registrableDomain(fav.hostname);
      const owner = Object.entries(BRANDS).find(([, ds]) => ds.some((d) => registrableDomain(d) === favSite));
      if (favSite !== site && owner && !BRANDS[owner[0]].some((d) => registrableDomain(d) === site)) add("brand_favicon", 18, `Favicon loaded from ${owner[0]}'s servers`, fav.hostname);
    } catch {
      /* ignore */
    }
  }
  const tp = p.thirdParties || [];
  const brandAssets = tp.filter((t) => Object.values(BRANDS).some((ds) => ds.some((d) => registrableDomain(d) === t.site)) && t.loaded && (t.kinds.img || t.kinds.style || t.kinds.script));
  if (pwForms.length && brandAssets.length) add("brand_assets", 10, "Loads images/styles from a brand's own servers", brandAssets.slice(0, 3).map((t) => t.host).join(", "));

  // --- Behaviour (from the page collector) ----------------------------------------
  const fl = p.flags || {};
  if (fl.rightClickBlocked) add("no_right_click", 5, "Right-click / text selection is blocked", "A common trick to hinder inspection.");
  if (fl.devtoolsDetect) add("devtools_detect", 8, "Tries to detect developer tools", "");
  if (fl.obfuscated) add("obfuscated_js", 10, "Heavily obfuscated inline JavaScript", fl.obfuscated);
  if (fl.metaRefresh) add("meta_refresh", 5, "Meta-refresh redirect", fl.metaRefresh);
  if (fl.fullPageIframe) add("full_iframe", 12, "Whole page is an iframe of another site", fl.fullPageIframe);
  if (fl.noIndex && pwForms.length) add("noindex_login", 4, "Login page asks search engines not to index it", "");
  if (fl.walletConnect && (urgency.length || /airdrop|claim|mint|reward/i.test(text))) add("drainer", 25, "Wallet-connect prompt with airdrop/claim lure", "Typical crypto-drainer pattern.");
  if (fl.clipboardWrite && /win\s*\+\s*r|powershell|cmd(?:\.exe)?|run dialog|verify you are human|press ctrl\s*\+\s*v/i.test(text)) add("clickfix", 35, "Asks you to paste a command into Run/terminal (ClickFix)", "Fake CAPTCHA that copies a malicious command to your clipboard.");

  // --- Domain age (RDAP) -----------------------------------------------------------
  if (typeof p.domainAgeDays === "number") {
    if (p.domainAgeDays < 30) add("new_domain", 25, "Domain registered less than 30 days ago", `${p.domainAgeDays} days old`);
    else if (p.domainAgeDays < 180) add("young_domain", 10, "Domain registered less than 6 months ago", `${p.domainAgeDays} days old`);
  }

  // A login form is the precondition for most phishing; without one, damp the score.
  const raw = signals.reduce((s, x) => s + x.weight, 0);
  const sensitive = pwForms.length || cardForms.length || signals.some((s) => ["seed_phrase", "drainer", "clickfix", "form_exfil"].includes(s.id));
  const score = Math.min(100, Math.round(sensitive ? raw : raw * 0.5));
  const level = score >= 60 ? "high" : score >= 30 ? "medium" : score >= 10 ? "low" : "minimal";
  signals.sort((a, b) => b.weight - a.weight);
  return { score, level, signals, brands: [...new Set(brandsSeen)], sensitiveForm: !!sensitive };
}

/** Re-score after domain age becomes known (from RDAP), without re-collecting the page. */
export function applyDomainAge(phishing, days) {
  if (!phishing || typeof days !== "number") return phishing;
  const signals = phishing.signals.filter((s) => s.id !== "new_domain" && s.id !== "young_domain");
  if (days < 30) signals.push({ id: "new_domain", weight: 25, title: "Domain registered less than 30 days ago", detail: `${days} days old` });
  else if (days < 180) signals.push({ id: "young_domain", weight: 10, title: "Domain registered less than 6 months ago", detail: `${days} days old` });
  signals.sort((a, b) => b.weight - a.weight);
  const raw = signals.reduce((s, x) => s + x.weight, 0);
  const score = Math.min(100, Math.round(phishing.sensitiveForm ? raw : raw * 0.5));
  const level = score >= 60 ? "high" : score >= 30 ? "medium" : score >= 10 ? "low" : "minimal";
  return { ...phishing, signals, score, level, domainAgeDays: days };
}
