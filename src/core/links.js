// Link and resource analysis: categorises every link by file type, flags files
// worth checking (documents, dumps, configs, archives), finds credentials in
// URLs, and maps every third-party host the page links to or loads from.

import { registrableDomain, normalizeHost, isIP } from "./domain.js";
import { urlSecrets } from "./exposures.js";
import { safeUrl, safeDecode } from "./util.js";

export const CATEGORIES = {
  document: ["pdf", "doc", "docx", "docm", "odt", "rtf", "txt", "md", "xls", "xlsx", "xlsm", "xlsb", "ods", "csv", "tsv", "ppt", "pptx", "pptm", "odp", "pages", "numbers", "key", "epub", "msg", "eml", "vcf", "ics"],
  data: ["sql", "db", "sqlite", "sqlite3", "mdb", "accdb", "bak", "backup", "old", "orig", "dump", "json", "xml", "yml", "yaml", "log", "parquet", "jsonl", "ndjson", "har", "swp", "tmp"],
  config: ["env", "ini", "conf", "config", "cfg", "properties", "toml", "pem", "crt", "cer", "der", "p12", "pfx", "jks", "keystore", "kdbx", "ovpn", "ppk", "pub", "key", "htpasswd", "htaccess", "npmrc", "pgpass", "netrc", "rdp", "git", "svn", "ds_store", "map"],
  archive: ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "iso", "img", "dmg", "war", "ear"],
  executable: ["exe", "msi", "pkg", "app", "apk", "aab", "ipa", "deb", "rpm", "appimage", "sh", "bash", "bat", "cmd", "ps1", "psm1", "vbs", "jar", "scr", "dll", "hta", "lnk", "js_", "wsf", "reg", "xll", "one"],
  image: ["png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "tif", "tiff", "heic", "heif", "avif", "raw", "cr2", "nef", "dng", "psd"],
  media: ["mp3", "mp4", "m4a", "m4v", "wav", "ogg", "webm", "mov", "avi", "mkv", "flac", "aac", "wmv"],
  web: ["html", "htm", "php", "asp", "aspx", "jsp", "cfm", "shtml", "xhtml", "js", "mjs", "css", "cgi", "pl"]
};

const EXT_TO_CAT = Object.fromEntries(Object.entries(CATEGORIES).flatMap(([cat, exts]) => exts.map((e) => [e, cat])));
// "key" is both a Keynote document and a private key; treat it as the riskier one.
EXT_TO_CAT.key = "config";
export const NOTABLE_CATEGORIES = new Set(["document", "data", "config", "archive", "executable"]);

/** File extension of a URL path ("report.final.PDF" -> "pdf"), or "". */
export function extOf(pathname) {
  const last = safeDecode(pathname || "").split("/").pop() || "";
  if (/^\.[a-z0-9_]+$/i.test(last)) return last.slice(1).toLowerCase(); // ".env", ".git"
  const m = /\.([a-z0-9_]{1,10})$/i.exec(last);
  return m ? m[1].toLowerCase() : "";
}

/** Well-known third-party services: [host suffix, service, category]. */
const SERVICES = [
  ["google-analytics.com", "Google Analytics", "analytics"], ["analytics.google.com", "Google Analytics", "analytics"],
  ["googletagmanager.com", "Google Tag Manager", "tag manager"], ["doubleclick.net", "Google Ads (DoubleClick)", "ads"],
  ["googlesyndication.com", "Google AdSense", "ads"], ["googleadservices.com", "Google Ads", "ads"], ["adservice.google.com", "Google Ads", "ads"],
  ["google.com/recaptcha", "reCAPTCHA", "security"], ["recaptcha.net", "reCAPTCHA", "security"], ["gstatic.com", "Google static", "cdn"],
  ["googleapis.com", "Google APIs", "cdn"], ["fonts.googleapis.com", "Google Fonts", "fonts"], ["fonts.gstatic.com", "Google Fonts", "fonts"],
  ["youtube.com", "YouTube", "video"], ["youtube-nocookie.com", "YouTube", "video"], ["ytimg.com", "YouTube", "video"], ["googlevideo.com", "YouTube", "video"],
  ["facebook.net", "Meta", "ads"], ["facebook.com", "Meta", "social"], ["fbcdn.net", "Meta", "social"], ["instagram.com", "Instagram", "social"],
  ["twitter.com", "X / Twitter", "social"], ["x.com", "X / Twitter", "social"], ["twimg.com", "X / Twitter", "social"], ["ads-twitter.com", "X Ads", "ads"],
  ["linkedin.com", "LinkedIn", "social"], ["licdn.com", "LinkedIn", "social"], ["ads.linkedin.com", "LinkedIn Ads", "ads"],
  ["tiktok.com", "TikTok", "social"], ["tiktokcdn.com", "TikTok", "social"], ["analytics.tiktok.com", "TikTok Pixel", "ads"],
  ["pinterest.com", "Pinterest", "social"], ["pinimg.com", "Pinterest", "social"], ["snapchat.com", "Snapchat", "ads"], ["sc-static.net", "Snapchat", "ads"],
  ["reddit.com", "Reddit", "social"], ["redditstatic.com", "Reddit", "ads"], ["bing.com", "Microsoft Bing", "ads"], ["clarity.ms", "Microsoft Clarity", "session replay"],
  ["hotjar.com", "Hotjar", "session replay"], ["hotjar.io", "Hotjar", "session replay"], ["fullstory.com", "FullStory", "session replay"],
  ["mouseflow.com", "Mouseflow", "session replay"], ["smartlook.com", "Smartlook", "session replay"], ["luckyorange.com", "Lucky Orange", "session replay"],
  ["yandex.ru", "Yandex", "analytics"], ["mc.yandex.ru", "Yandex Metrica", "analytics"], ["yastatic.net", "Yandex", "cdn"],
  ["segment.com", "Segment", "analytics"], ["segment.io", "Segment", "analytics"], ["mixpanel.com", "Mixpanel", "analytics"], ["amplitude.com", "Amplitude", "analytics"],
  ["heap.io", "Heap", "analytics"], ["heapanalytics.com", "Heap", "analytics"], ["posthog.com", "PostHog", "analytics"], ["plausible.io", "Plausible", "analytics"],
  ["usefathom.com", "Fathom", "analytics"], ["matomo.cloud", "Matomo", "analytics"], ["quantserve.com", "Quantcast", "ads"], ["scorecardresearch.com", "Comscore", "analytics"],
  ["chartbeat.com", "Chartbeat", "analytics"], ["newrelic.com", "New Relic", "monitoring"], ["nr-data.net", "New Relic", "monitoring"],
  ["sentry.io", "Sentry", "monitoring"], ["sentry-cdn.com", "Sentry", "monitoring"], ["datadoghq.com", "Datadog", "monitoring"], ["datadoghq-browser-agent.com", "Datadog", "monitoring"],
  ["bugsnag.com", "Bugsnag", "monitoring"], ["rollbar.com", "Rollbar", "monitoring"], ["logrocket.com", "LogRocket", "session replay"], ["lr-ingest.io", "LogRocket", "session replay"],
  ["criteo.com", "Criteo", "ads"], ["criteo.net", "Criteo", "ads"], ["taboola.com", "Taboola", "ads"], ["outbrain.com", "Outbrain", "ads"], ["adnxs.com", "Xandr / AppNexus", "ads"],
  ["rubiconproject.com", "Magnite", "ads"], ["pubmatic.com", "PubMatic", "ads"], ["openx.net", "OpenX", "ads"], ["casalemedia.com", "Index Exchange", "ads"],
  ["amazon-adsystem.com", "Amazon Ads", "ads"], ["adsrvr.org", "The Trade Desk", "ads"], ["demdex.net", "Adobe Audience Manager", "ads"], ["omtrdc.net", "Adobe Analytics", "analytics"],
  ["adobedtm.com", "Adobe Launch", "tag manager"], ["tealiumiq.com", "Tealium", "tag manager"], ["tiqcdn.com", "Tealium", "tag manager"],
  ["hubspot.com", "HubSpot", "marketing"], ["hs-scripts.com", "HubSpot", "marketing"], ["hsforms.net", "HubSpot", "marketing"], ["hs-analytics.net", "HubSpot", "marketing"], ["hubspot.net", "HubSpot", "marketing"],
  ["marketo.net", "Marketo", "marketing"], ["mktoresp.com", "Marketo", "marketing"], ["pardot.com", "Salesforce Pardot", "marketing"], ["klaviyo.com", "Klaviyo", "marketing"],
  ["list-manage.com", "Mailchimp", "marketing"], ["mailchimp.com", "Mailchimp", "marketing"], ["chimpstatic.com", "Mailchimp", "marketing"],
  ["intercom.io", "Intercom", "support"], ["intercomcdn.com", "Intercom", "support"], ["zdassets.com", "Zendesk", "support"], ["zendesk.com", "Zendesk", "support"],
  ["drift.com", "Drift", "support"], ["crisp.chat", "Crisp", "support"], ["tawk.to", "Tawk.to", "support"], ["livechatinc.com", "LiveChat", "support"], ["tidio.co", "Tidio", "support"],
  ["freshchat.com", "Freshchat", "support"], ["jivosite.com", "JivoChat", "support"], ["olark.com", "Olark", "support"],
  ["cookielaw.org", "OneTrust", "consent"], ["onetrust.com", "OneTrust", "consent"], ["cookiebot.com", "Cookiebot", "consent"], ["usercentrics.eu", "Usercentrics", "consent"],
  ["consentmanager.net", "consentmanager", "consent"], ["didomi.io", "Didomi", "consent"], ["trustarc.com", "TrustArc", "consent"], ["quantcast.mgr.consensu.org", "Quantcast Choice", "consent"],
  ["stripe.com", "Stripe", "payments"], ["stripe.network", "Stripe", "payments"], ["paypal.com", "PayPal", "payments"], ["paypalobjects.com", "PayPal", "payments"],
  ["braintreegateway.com", "Braintree", "payments"], ["adyen.com", "Adyen", "payments"], ["klarna.com", "Klarna", "payments"], ["squareup.com", "Square", "payments"],
  ["cloudflare.com", "Cloudflare", "cdn"], ["cdnjs.cloudflare.com", "cdnjs", "cdn"], ["cloudflareinsights.com", "Cloudflare Web Analytics", "analytics"],
  ["jsdelivr.net", "jsDelivr", "cdn"], ["unpkg.com", "unpkg", "cdn"], ["bootstrapcdn.com", "BootstrapCDN", "cdn"], ["jquery.com", "jQuery CDN", "cdn"],
  ["akamaihd.net", "Akamai", "cdn"], ["akamaized.net", "Akamai", "cdn"], ["fastly.net", "Fastly", "cdn"], ["cloudfront.net", "Amazon CloudFront", "cdn"],
  ["amazonaws.com", "Amazon Web Services", "cloud"], ["azureedge.net", "Azure CDN", "cdn"], ["windows.net", "Microsoft Azure", "cloud"], ["azurewebsites.net", "Azure App Service", "cloud"],
  ["googleusercontent.com", "Google Cloud", "cloud"], ["storage.googleapis.com", "Google Cloud Storage", "cloud"], ["firebaseio.com", "Firebase", "cloud"], ["firebasestorage.googleapis.com", "Firebase Storage", "cloud"],
  ["supabase.co", "Supabase", "cloud"], ["vercel.app", "Vercel", "cloud"], ["netlify.app", "Netlify", "cloud"], ["herokuapp.com", "Heroku", "cloud"],
  ["shopify.com", "Shopify", "commerce"], ["shopifycdn.com", "Shopify", "commerce"], ["myshopify.com", "Shopify", "commerce"], ["bigcommerce.com", "BigCommerce", "commerce"],
  ["wixstatic.com", "Wix", "cdn"], ["parastorage.com", "Wix", "cdn"], ["squarespace.com", "Squarespace", "cdn"], ["website-files.com", "Webflow", "cdn"],
  ["wp.com", "WordPress.com / Jetpack", "cdn"], ["gravatar.com", "Gravatar", "social"], ["typekit.net", "Adobe Fonts", "fonts"], ["fontawesome.com", "Font Awesome", "fonts"],
  ["vimeo.com", "Vimeo", "video"], ["vimeocdn.com", "Vimeo", "video"], ["wistia.com", "Wistia", "video"], ["jwplayer.com", "JW Player", "video"], ["brightcove.net", "Brightcove", "video"],
  ["spotify.com", "Spotify", "media"], ["soundcloud.com", "SoundCloud", "media"], ["disqus.com", "Disqus", "comments"], ["disquscdn.com", "Disqus", "comments"],
  ["addthis.com", "AddThis", "social"], ["sharethis.com", "ShareThis", "social"], ["addtoany.com", "AddToAny", "social"],
  ["maps.googleapis.com", "Google Maps", "maps"], ["mapbox.com", "Mapbox", "maps"], ["openstreetmap.org", "OpenStreetMap", "maps"], ["arcgis.com", "Esri ArcGIS", "maps"],
  ["hcaptcha.com", "hCaptcha", "security"], ["challenges.cloudflare.com", "Cloudflare Turnstile", "security"], ["polyfill.io", "polyfill.io (compromised)", "cdn"],
  ["github.com", "GitHub", "code"], ["githubusercontent.com", "GitHub", "code"], ["github.io", "GitHub Pages", "cloud"], ["gitlab.com", "GitLab", "code"],
  ["algolia.net", "Algolia", "search"], ["algolianet.com", "Algolia", "search"], ["auth0.com", "Auth0", "identity"], ["okta.com", "Okta", "identity"],
  ["onesignal.com", "OneSignal", "push"], ["pusher.com", "Pusher", "realtime"], ["optimizely.com", "Optimizely", "experimentation"], ["vwo.com", "VWO", "experimentation"],
  ["trustpilot.com", "Trustpilot", "reviews"], ["calendly.com", "Calendly", "scheduling"], ["typeform.com", "Typeform", "forms"], ["jotform.com", "Jotform", "forms"],
  ["web3modal.org", "WalletConnect / Reown", "crypto"], ["walletconnect.com", "WalletConnect", "crypto"], ["walletconnect.org", "WalletConnect", "crypto"],
  ["infura.io", "Infura", "crypto"], ["alchemy.com", "Alchemy", "crypto"], ["api.telegram.org", "Telegram Bot API", "messaging"], ["discord.com", "Discord", "social"]
];

/** Identify a third-party service from a host (longest suffix wins). */
export function classifyHost(host) {
  host = normalizeHost(host);
  let best = null;
  for (const [suffix, name, category] of SERVICES) {
    const s = suffix.split("/")[0];
    if (host === s || host.endsWith(`.${s}`)) {
      if (!best || s.length > best.len) best = { name, category, len: s.length };
    }
  }
  return best ? { name: best.name, category: best.category } : null;
}

/**
 * Analyse links found on the page.
 * @param {Array<{href:string,text?:string,rel?:string,kind?:string}>} raw
 * @param {string} pageUrl
 */
export function analyzeLinks(raw, pageUrl) {
  const page = safeUrl(pageUrl);
  const pageSite = page ? registrableDomain(page.hostname) : "";
  const seen = new Map();
  for (const l of raw || []) {
    const u = safeUrl(l.href, pageUrl);
    if (!u) continue;
    if (/^(javascript|data|blob|about|chrome|chrome-extension):$/.test(u.protocol)) continue;
    const clean = u.href.replace(/#.*$/, "");
    if (page && clean === page.href.replace(/#.*$/, "") && u.hash) continue; // in-page anchor
    const prev = seen.get(clean);
    if (prev) {
      prev.count++;
      if (!prev.text && l.text) prev.text = l.text;
      continue;
    }
    let category = "page";
    let ext = "";
    if (u.protocol === "mailto:") category = "email";
    else if (u.protocol === "tel:" || u.protocol === "sms:") category = "phone";
    else if (!/^https?:$/.test(u.protocol)) category = "other";
    else {
      ext = extOf(u.pathname);
      if (ext) category = EXT_TO_CAT[ext] || "other";
    }
    const host = /^https?:$/.test(u.protocol) ? u.hostname.toLowerCase() : "";
    const external = !!host && registrableDomain(host) !== pageSite;
    const secrets = /^https?:$/.test(u.protocol) ? urlSecrets(clean) : [];
    const insecure = u.protocol === "http:" && page?.protocol === "https:";
    seen.set(clean, {
      url: clean,
      text: (l.text || "").slice(0, 160),
      rel: l.rel || "",
      host,
      ext,
      category,
      external,
      insecure,
      ipHost: isIP(host),
      secretParams: secrets.map((s) => s.param),
      secrets,
      notable: NOTABLE_CATEGORIES.has(category) || secrets.length > 0,
      count: 1
    });
  }
  const links = [...seen.values()];
  links.sort((a, b) => Number(b.notable) - Number(a.notable) || Number(a.external) - Number(b.external) || a.url.localeCompare(b.url));
  return links;
}

/**
 * Third-party host map from everything the page loads or links to.
 * @param {Array<{url:string, kind:string}>} resources  kind: script|style|iframe|img|xhr|font|media|link|form|preconnect|other
 * @param {string} pageUrl
 */
export function thirdParties(resources, pageUrl) {
  const page = safeUrl(pageUrl);
  const pageSite = page ? registrableDomain(page.hostname) : "";
  const byHost = new Map();
  for (const r of resources || []) {
    const u = safeUrl(r.url, pageUrl);
    if (!u || !/^(https?|wss?):$/.test(u.protocol)) continue;
    const host = u.hostname.toLowerCase();
    const site = registrableDomain(host);
    if (site === pageSite) continue;
    let e = byHost.get(host);
    if (!e) {
      const svc = classifyHost(host);
      e = { host, site, service: svc?.name || null, category: svc?.category || "unknown", kinds: {}, count: 0, sample: u.href.slice(0, 300) };
      byHost.set(host, e);
    }
    e.count++;
    e.kinds[r.kind || "other"] = (e.kinds[r.kind || "other"] || 0) + 1;
  }
  const list = [...byHost.values()];
  const loadKinds = new Set(["script", "iframe", "xhr", "img", "style", "font", "media", "beacon", "other"]);
  for (const e of list) e.loaded = Object.keys(e.kinds).some((k) => loadKinds.has(k));
  list.sort((a, b) => Number(b.loaded) - Number(a.loaded) || b.count - a.count);
  return list;
}
