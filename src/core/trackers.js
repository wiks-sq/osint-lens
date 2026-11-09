// Tracking, advertising, monitoring and verification identifiers.
//
// These are among the strongest pivots in website OSINT: an analytics or ad
// account ID belongs to the *owner*, not the site, so two sites sharing one
// (say a Google AdSense publisher ID or a Sentry organisation) are very likely
// run by the same person or company. Reverse lookups (see pivots.js) find the
// other sites.
//
// Rule fields:
//   id      stable id         vendor  display name     kind  category
//   text    RegExp run over page HTML/script text (group 1 = ID)
//   url     RegExp run over resource and link URLs (group 1 = ID)
//   strong  true when the ID is unique to an account and good for linking sites

export const TRACKER_RULES = [
  // Google
  { id: "ga4", vendor: "Google Analytics 4", kind: "analytics", strong: true,
    text: /['"`=\s(,](G-[A-Z0-9]{8,12})['"`&\s),]/g, url: /[?&](?:id|tid)=(G-[A-Z0-9]{8,12})\b/g },
  { id: "ua", vendor: "Google Universal Analytics", kind: "analytics", strong: true,
    text: /\b(UA-\d{4,10}-\d{1,4})\b/g, url: /[?&](?:id|tid)=(UA-\d{4,10}-\d{1,4})\b/g },
  { id: "gtm", vendor: "Google Tag Manager", kind: "tag manager", strong: true,
    text: /\b(GTM-[A-Z0-9]{4,9})\b/g, url: /[?&]id=(GTM-[A-Z0-9]{4,9})\b/g },
  { id: "gads", vendor: "Google Ads", kind: "ads", strong: true,
    text: /['"`=\s(,/](AW-\d{8,12})\b/g, url: /[?&]id=(AW-\d{8,12})\b/g },
  { id: "gdc", vendor: "Google Floodlight / DV360", kind: "ads", strong: true,
    text: /['"`=\s(,](DC-\d{6,10})\b/g, url: /[?&]id=(DC-\d{6,10})\b/g },
  { id: "adsense", vendor: "Google AdSense publisher", kind: "ads", strong: true,
    text: /\b(ca-pub-\d{10,20})\b|\b(pub-\d{16})\b/g, url: /[?&]client=(ca-pub-\d{10,20})\b/g },
  { id: "admob", vendor: "Google AdMob", kind: "ads", strong: true, text: /\b(ca-app-pub-\d{10,20}(?:~\d{8,12})?)\b/g },
  { id: "optimize", vendor: "Google Optimize", kind: "analytics", text: /\b(OPT-[A-Z0-9]{6,8})\b/g },
  { id: "gmaps_key", vendor: "Google Maps / Cloud API key", kind: "api key", strong: true,
    text: /\b(AIza[0-9A-Za-z_\-]{35})\b/g, url: /[?&]key=(AIza[0-9A-Za-z_\-]{35})\b/g },
  { id: "recaptcha", vendor: "Google reCAPTCHA site key", kind: "captcha", strong: true,
    text: /(?:data-sitekey|sitekey|render)['"]?\s*[=:]\s*['"](6L[0-9A-Za-z_\-]{38})['"]/g, url: /[?&](?:render|k)=(6L[0-9A-Za-z_\-]{38})\b/g },
  { id: "firebase", vendor: "Firebase project", kind: "backend", strong: true,
    text: /projectId['"]?\s*:\s*['"]([a-z0-9\-]{4,40})['"]|\b([a-z0-9\-]{4,40})\.firebaseio\.com\b|\b([a-z0-9\-]{4,40})\.firebaseapp\.com\b/g },
  { id: "gcs_client", vendor: "Google OAuth client ID", kind: "api key", strong: true, text: /\b(\d{6,14}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b/g },

  // Meta and other ad networks
  { id: "fb_pixel", vendor: "Meta (Facebook) Pixel", kind: "ads", strong: true,
    text: /fbq\(\s*['"]init['"]\s*,\s*['"](\d{12,17})['"]/g, url: /(?:facebook\.com\/tr\/?\?(?:[^"'\s]*&)?id=|connect\.facebook\.net\/signals\/config\/)(\d{12,17})/g },
  { id: "fb_app", vendor: "Facebook App ID", kind: "social", strong: true,
    text: /(?:fb:app_id['"]?\s+content=['"]|appId['"]?\s*:\s*['"])(\d{12,17})['"]/g, url: /[?&]app_id=(\d{12,17})\b/g },
  { id: "tiktok_pixel", vendor: "TikTok Pixel", kind: "ads", strong: true, text: /ttq\.load\(\s*['"]([A-Z0-9]{18,22})['"]/g, url: /analytics\.tiktok\.com\/i18n\/pixel\/events\.js\?sdkid=([A-Z0-9]{18,22})/g },
  { id: "linkedin_insight", vendor: "LinkedIn Insight Tag", kind: "ads", strong: true,
    text: /_linkedin_(?:data_)?partner_id\s*=\s*['"]?(\d{4,10})|_linkedin_data_partner_ids\.push\(\s*['"]?(\d{4,10})/g, url: /px\.ads\.linkedin\.com\/collect\/?\?(?:[^"'\s]*&)?pid=(\d{4,10})/g },
  { id: "twitter_pixel", vendor: "X (Twitter) Pixel", kind: "ads", strong: true, text: /twq\(\s*['"](?:init|config)['"]\s*,\s*['"]([a-z0-9]{5,8})['"]/g },
  { id: "pinterest_tag", vendor: "Pinterest Tag", kind: "ads", strong: true, text: /pintrk\(\s*['"]load['"]\s*,\s*['"](\d{10,16})['"]/g },
  { id: "snap_pixel", vendor: "Snap Pixel", kind: "ads", strong: true, text: /snaptr\(\s*['"]init['"]\s*,\s*['"]([0-9a-f\-]{36})['"]/g },
  { id: "reddit_pixel", vendor: "Reddit Pixel", kind: "ads", strong: true, text: /rdt\(\s*['"]init['"]\s*,\s*['"]([a-z0-9_]{6,30})['"]/g },
  { id: "bing_uet", vendor: "Microsoft Advertising UET", kind: "ads", strong: true, text: /\bti\s*:\s*['"](\d{6,10})['"]/g, url: /bat\.bing\.com\/action\/0\?(?:[^"'\s]*&)?ti=(\d{6,10})/g, needs: /bat\.bing\.com|uetq/ },
  { id: "criteo", vendor: "Criteo", kind: "ads", text: /criteo_q[\s\S]{0,200}?account\s*:\s*['"]?(\d{3,8})/g },
  { id: "taboola", vendor: "Taboola publisher", kind: "ads", strong: true, url: /cdn\.taboola\.com\/libtrc\/([a-z0-9\-]+)\/loader\.js/g },
  { id: "outbrain", vendor: "Outbrain", kind: "ads", text: /OB_ADV_ID\s*=\s*['"]?([0-9a-f]{20,40})/g },
  { id: "amazon_assoc", vendor: "Amazon Associates tag", kind: "affiliate", strong: true, url: /amazon\.[a-z.]+\/[^"'\s]*[?&]tag=([a-z0-9\-]{3,40}-2\d)\b/g },

  // Product analytics and session replay
  { id: "hotjar", vendor: "Hotjar", kind: "session replay", strong: true, text: /\bhjid\s*:\s*(\d{5,9})/g, url: /static\.hotjar\.com\/c\/hotjar-(\d{5,9})\.js/g },
  { id: "clarity", vendor: "Microsoft Clarity", kind: "session replay", strong: true, text: /clarity\.ms\/tag\/([a-z0-9]{8,12})|["']clarity["']\s*,\s*["']script["']\s*,\s*["']([a-z0-9]{8,12})["']/g, url: /clarity\.ms\/tag\/([a-z0-9]{8,12})/g },
  { id: "yandex_metrica", vendor: "Yandex Metrica", kind: "analytics", strong: true, text: /ym\(\s*(\d{6,10})\s*,\s*['"]init['"]|yaCounter(\d{6,10})/g, url: /mc\.yandex\.ru\/watch\/(\d{6,10})/g },
  { id: "matomo", vendor: "Matomo / Piwik site", kind: "analytics", text: /_paq\.push\(\s*\[\s*['"]setSiteId['"]\s*,\s*['"]?(\d{1,6})['"]?\s*\]/g },
  { id: "matomo_host", vendor: "Matomo tracker host", kind: "analytics", strong: true, text: /_paq\.push\(\s*\[\s*['"]setTrackerUrl['"]\s*,\s*[^)]*?['"](?:https?:)?\/\/([a-z0-9.\-]+)/g },
  { id: "plausible", vendor: "Plausible domain", kind: "analytics", text: /data-domain=['"]([a-z0-9.\-,]+)['"][^>]*plausible|plausible[^>]*data-domain=['"]([a-z0-9.\-,]+)['"]/g },
  { id: "segment", vendor: "Segment write key", kind: "analytics", strong: true, text: /analytics\.load\(\s*['"]([A-Za-z0-9]{20,40})['"]/g, url: /cdn\.segment\.com\/analytics\.js\/v1\/([A-Za-z0-9]{20,40})\//g },
  { id: "mixpanel", vendor: "Mixpanel project token", kind: "analytics", strong: true, text: /mixpanel\.init\(\s*['"]([a-f0-9]{32})['"]/g },
  { id: "amplitude", vendor: "Amplitude API key", kind: "analytics", strong: true, text: /amplitude[\s\S]{0,40}?\.init\(\s*['"]([a-f0-9]{32})['"]/g },
  { id: "heap", vendor: "Heap", kind: "analytics", strong: true, text: /heap\.load\(\s*['"](\d{6,12})['"]/g },
  { id: "posthog", vendor: "PostHog project key", kind: "analytics", strong: true, text: /\b(phc_[A-Za-z0-9]{32,50})\b/g },
  { id: "fullstory", vendor: "FullStory org", kind: "session replay", strong: true, text: /_fs_org['"]?\]?\s*=\s*['"]([A-Z0-9\-]{4,12})['"]/g },
  { id: "cf_beacon", vendor: "Cloudflare Web Analytics", kind: "analytics", strong: true, text: /data-cf-beacon=['"][^'"]*?token["\\]*:\s*["\\]*([a-f0-9]{32})/g },
  { id: "newrelic", vendor: "New Relic", kind: "monitoring", strong: true, text: /(?:applicationID|licenseKey)["']?\s*:\s*["']([A-Za-z0-9\-]{6,40})["']/g, needs: /newrelic|NREUM/ },
  { id: "sentry", vendor: "Sentry DSN", kind: "monitoring", strong: true, text: /https:\/\/([a-f0-9]{32})@(?:o\d+\.)?(?:[a-z0-9.\-]*\.)?sentry\.io\/\d+/g },
  { id: "sentry_org", vendor: "Sentry organisation", kind: "monitoring", strong: true, text: /@(o\d{4,10})\.ingest(?:\.[a-z]{2})?\.sentry\.io/g },
  { id: "bugsnag", vendor: "Bugsnag API key", kind: "monitoring", strong: true, text: /bugsnag[\s\S]{0,60}?apiKey['"]?\s*:\s*['"]([a-f0-9]{32})['"]/gi },
  { id: "datadog_rum", vendor: "Datadog RUM client token", kind: "monitoring", strong: true, text: /\b(pub[a-f0-9]{32})\b/g },

  // Chat, CRM and support widgets
  { id: "intercom", vendor: "Intercom app", kind: "support", strong: true, text: /intercomSettings[\s\S]{0,200}?app_id['"]?\s*:\s*['"]([a-z0-9]{8})['"]/g, url: /widget\.intercom\.io\/widget\/([a-z0-9]{8})/g },
  { id: "hubspot", vendor: "HubSpot portal", kind: "crm", strong: true, url: /js(?:-[a-z0-9]+)?\.(?:hs-scripts|hs-analytics|hsforms|hubspot|usemessages|hs-banner)\.(?:com|net)\/(?:[a-z0-9\-]+\/)?(\d{5,10})\.js/g, text: /portalId['"]?\s*:\s*['"]?(\d{5,10})/g },
  { id: "drift", vendor: "Drift", kind: "support", strong: true, text: /drift\.load\(\s*['"]([a-z0-9]{8,14})['"]/g },
  { id: "crisp", vendor: "Crisp website", kind: "support", strong: true, text: /CRISP_WEBSITE_ID\s*=\s*['"]([0-9a-f\-]{36})['"]/g },
  { id: "tawk", vendor: "Tawk.to property", kind: "support", strong: true, url: /embed\.tawk\.to\/([0-9a-f]{24})\/([a-z0-9]+)/g },
  { id: "zendesk", vendor: "Zendesk", kind: "support", strong: true, url: /static\.zdassets\.com\/ekr\/snippet\.js\?key=([0-9a-f\-]{36})/g, text: /\b([a-z0-9\-]{2,60})\.zendesk\.com\b/g },
  { id: "freshdesk", vendor: "Freshworks", kind: "support", strong: true, text: /\b([a-z0-9\-]{2,60})\.(?:freshdesk|freshchat|freshservice)\.com\b/g },
  { id: "livechat", vendor: "LiveChat licence", kind: "support", strong: true, text: /__lc\.license\s*=\s*(\d{5,10})/g },
  { id: "tidio", vendor: "Tidio", kind: "support", strong: true, url: /code\.tidio\.co\/([a-z0-9]{20,40})\.js/g },
  { id: "jivo", vendor: "JivoChat", kind: "support", strong: true, url: /code\.jivo(?:site)?\.(?:com|ru)\/widget\/([A-Za-z0-9]{8,12})/g },
  { id: "onesignal", vendor: "OneSignal app", kind: "push", strong: true, text: /appId['"]?\s*:\s*['"]([0-9a-f\-]{36})['"][\s\S]{0,80}?(?:safari_web_id|OneSignal)|OneSignal[\s\S]{0,200}?appId['"]?\s*:\s*['"]([0-9a-f\-]{36})['"]/g },
  { id: "mailchimp_list", vendor: "Mailchimp audience", kind: "email marketing", strong: true, url: /([a-z0-9\-]+)\.us\d{1,2}\.list-manage\.com\/subscribe\/post\?u=([0-9a-f]{25})/g },
  { id: "klaviyo", vendor: "Klaviyo company", kind: "email marketing", strong: true, url: /static\.klaviyo\.com\/onsite\/js\/(?:klaviyo\.js\?company_id=)?([A-Za-z0-9]{6})/g },

  // Commerce, payments, maps, search
  { id: "shopify_store", vendor: "Shopify store", kind: "commerce", strong: true, text: /Shopify\.shop\s*=\s*['"]([a-z0-9\-]+\.myshopify\.com)['"]|\b([a-z0-9\-]+\.myshopify\.com)\b/g },
  { id: "stripe_pk", vendor: "Stripe publishable key", kind: "payments", strong: true, text: /\b(pk_live_[A-Za-z0-9]{20,})\b/g },
  { id: "paypal_client", vendor: "PayPal client ID", kind: "payments", strong: true, url: /paypal\.com\/sdk\/js\?(?:[^"'\s]*&)?client-id=([A-Za-z0-9_\-]{40,90})/g },
  { id: "braintree", vendor: "Braintree tokenization key", kind: "payments", strong: true, text: /\b((?:production|sandbox)_[a-z0-9]{8}_[a-z0-9]{16})\b/g },
  { id: "mapbox", vendor: "Mapbox public token", kind: "maps", strong: true, text: /\b(pk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{20,})\b/g },
  { id: "algolia", vendor: "Algolia application", kind: "search", strong: true, text: /(?:appId|applicationId|ALGOLIA_APP_ID)['"]?\s*[:=]\s*['"]([A-Z0-9]{10})['"]/g, url: /https:\/\/([A-Z0-9]{10})-dsn\.algolia\.net/gi },
  { id: "hcaptcha", vendor: "hCaptcha site key", kind: "captcha", strong: true, text: /data-sitekey=['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]/g },
  { id: "turnstile", vendor: "Cloudflare Turnstile site key", kind: "captcha", strong: true, text: /\b(0x4AAAAAAA[A-Za-z0-9_\-]{12,30})\b/g },
  { id: "cookiebot", vendor: "Cookiebot domain group", kind: "consent", strong: true, text: /data-cbid=['"]([0-9a-f\-]{36})['"]/g },
  { id: "onetrust", vendor: "OneTrust domain script", kind: "consent", strong: true, text: /data-domain-script=['"]([0-9a-f\-]{36}(?:-test)?)['"]/g },
  { id: "auth0", vendor: "Auth0 tenant", kind: "identity", strong: true, text: /\b([a-z0-9\-]+(?:\.[a-z]{2})?\.auth0\.com)\b/g },
  { id: "okta", vendor: "Okta tenant", kind: "identity", strong: true, text: /\b([a-z0-9\-]+\.(?:okta|oktapreview)\.com)\b/g },
  { id: "cognito", vendor: "AWS Cognito pool", kind: "identity", strong: true, text: /\b((?:us|eu|ap|ca|sa|me|af)-[a-z]+-\d:[0-9a-f\-]{36})\b|\b((?:us|eu|ap|ca|sa|me|af)-[a-z]+-\d_[A-Za-z0-9]{9})\b/g },
  { id: "supabase", vendor: "Supabase project", kind: "backend", strong: true, text: /\b([a-z]{20})\.supabase\.co\b/g },
  { id: "aws_appsync", vendor: "AWS AppSync endpoint", kind: "backend", strong: true, text: /\b([a-z0-9]{26})\.appsync-api\.[a-z0-9\-]+\.amazonaws\.com\b/g },
  { id: "aws_apigw", vendor: "AWS API Gateway", kind: "backend", strong: true, text: /\b([a-z0-9]{10})\.execute-api\.[a-z0-9\-]+\.amazonaws\.com\b/g }
];

/** <meta name=...> verification tokens. Each is tied to the account that verified the domain. */
export const VERIFICATION_META = {
  "google-site-verification": "Google Search Console",
  "msvalidate.01": "Bing Webmaster",
  "yandex-verification": "Yandex Webmaster",
  "facebook-domain-verification": "Meta (Facebook) domain",
  "p:domain_verify": "Pinterest",
  "baidu-site-verification": "Baidu",
  "norton-safeweb-site-verification": "Norton Safe Web",
  "ahrefs-site-verification": "Ahrefs",
  "majestic-site-verification": "Majestic",
  "alexaverifyid": "Alexa",
  "naver-site-verification": "Naver",
  "seznam-wmt": "Seznam",
  "wot-verification": "WOT",
  "yahoo-site-verification": "Yahoo",
  "apple-domain-verification": "Apple",
  "atlassian-domain-verification": "Atlassian",
  "zoom-domain-verification": "Zoom",
  "docusign": "DocuSign",
  "detectify-verification": "Detectify",
  "tiktok-developers-site-verification": "TikTok",
  "shopify-checkout-api-token": "Shopify checkout",
  "brave-rewards-verification": "Brave Rewards",
  "fediverse:creator": "Fediverse creator"
};

/** TXT record prefixes that verify domain ownership with a service (from DNS). */
export const VERIFICATION_TXT = [
  [/^google-site-verification=(.+)$/i, "Google Search Console"],
  [/^MS=(ms\d+)$/i, "Microsoft 365"],
  [/^facebook-domain-verification=(.+)$/i, "Meta (Facebook) domain"],
  [/^apple-domain-verification=(.+)$/i, "Apple"],
  [/^atlassian-domain-verification=(.+)$/i, "Atlassian"],
  [/^docusign=(.+)$/i, "DocuSign"],
  [/^adobe-idp-site-verification=(.+)$/i, "Adobe"],
  [/^zoom-domain-verification=?(.+)$/i, "Zoom"],
  [/^stripe-verification=(.+)$/i, "Stripe"],
  [/^globalsign-domain-verification=(.+)$/i, "GlobalSign"],
  [/^_?globalsign-domain-verification=(.+)$/i, "GlobalSign"],
  [/^amazonses:(.+)$/i, "Amazon SES"],
  [/^yandex-verification:\s*(.+)$/i, "Yandex"],
  [/^hubspot-developer-verification=(.+)$/i, "HubSpot"],
  [/^openai-domain-verification=(.+)$/i, "OpenAI"],
  [/^slack-domain-verification=(.+)$/i, "Slack"],
  [/^dropbox-domain-verification=(.+)$/i, "Dropbox"],
  [/^cisco-ci-domain-verification=(.+)$/i, "Cisco Webex"],
  [/^miro-verification=(.+)$/i, "Miro"],
  [/^notion-domain-verification=(.+)$/i, "Notion"],
  [/^canva-site-verification=(.+)$/i, "Canva"],
  [/^twilio-domain-verification=(.+)$/i, "Twilio"],
  [/^mailru-verification:\s*(.+)$/i, "Mail.ru"],
  [/^pardot\d*=(.+)$/i, "Salesforce Pardot"],
  [/^citrix-verification-code=(.+)$/i, "Citrix"],
  [/^teamviewer-sso-verification=(.+)$/i, "TeamViewer"],
  [/^v=verifydomain MS=(.+)$/i, "Microsoft"],
  [/^keybase-site-verification=(.+)$/i, "Keybase"],
  [/^brave-ledger-verification=(.+)$/i, "Brave"],
  [/^have-i-been-pwned-verification=(.+)$/i, "Have I Been Pwned"],
  [/^wiz-domain-verification=(.+)$/i, "Wiz"],
  [/^onetrust-domain-verification=(.+)$/i, "OneTrust"],
  [/^knowbe4-site-verification=(.+)$/i, "KnowBe4"],
  [/^segment-site-verification=(.+)$/i, "Segment"],
  [/^postman-domain-verification=(.+)$/i, "Postman"],
  [/^github-verification=(.+)$/i, "GitHub"],
  [/^_github-challenge/i, "GitHub"],
  // Generic "<service>-domain-verification=<token>" and "<service>-site-verification=<token>".
  [/^([a-z0-9_\-]+?)-(?:site-|domain-)?verification(?:-[a-z0-9]+)?[=:]\s*(.+)$/i, null]
];

/** Match a DNS TXT record against the verification patterns. Returns { service, token } or null. */
export function verificationFromTxt(txt) {
  for (const [re, service] of VERIFICATION_TXT) {
    const m = re.exec(String(txt).trim());
    if (!m) continue;
    if (service) return { service, token: (m[1] || txt).trim() };
    const name = m[1].replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
    return { service: name, token: m[2].trim() };
  }
  return null;
}

const IGNORE_IDS = new Set(["G-XXXXXXXXXX", "UA-XXXXX-Y", "GTM-XXXXXX", "UA-000000-1", "GTM-XXXX"]);

/**
 * Find tracker IDs in text (HTML, inline/external script source).
 * @returns {Array<{rule:string, vendor:string, kind:string, value:string, strong:boolean, source:string}>}
 */
export function findTrackersInText(text, source = "html") {
  const out = [];
  if (!text) return out;
  for (const r of TRACKER_RULES) {
    if (!r.text) continue;
    if (r.needs && !r.needs.test(text)) continue;
    for (const m of text.matchAll(r.text)) {
      const v = m.slice(1).find(Boolean);
      if (v && !IGNORE_IDS.has(v)) out.push({ rule: r.id, vendor: r.vendor, kind: r.kind, value: v, strong: !!r.strong, source });
    }
  }
  return out;
}

/** Find tracker IDs in a resource or link URL. */
export function findTrackersInUrl(href, source = "resource") {
  const out = [];
  for (const r of TRACKER_RULES) {
    if (!r.url) continue;
    r.url.lastIndex = 0;
    for (const m of String(href).matchAll(r.url)) {
      const v = m.slice(1).filter(Boolean).join(r.id === "tawk" || r.id === "mailchimp_list" ? "/" : "");
      if (v && !IGNORE_IDS.has(v)) out.push({ rule: r.id, vendor: r.vendor, kind: r.kind, value: v, strong: !!r.strong, source });
    }
  }
  return out;
}

/** De-duplicate tracker hits by rule+value, merging sources. */
export function mergeTrackers(hits) {
  const map = new Map();
  for (const h of hits) {
    const k = `${h.rule}|${h.value}`;
    const cur = map.get(k);
    if (cur) {
      if (!cur.sources.includes(h.source)) cur.sources.push(h.source);
    } else {
      map.set(k, { ...h, sources: [h.source] });
    }
  }
  return [...map.values()].sort((a, b) => Number(b.strong) - Number(a.strong) || a.vendor.localeCompare(b.vendor));
}
