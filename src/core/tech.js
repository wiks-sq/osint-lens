// Technology fingerprinting, in the spirit of Wappalyzer but compact.
//
// Signals per technology (any one is enough; a capture group yields a version):
//   src      script/stylesheet/resource URLs
//   html     page HTML
//   meta     <meta name="generator"> content
//   header   { name: RegExp } on response headers
//   cookie   cookie names
//   global   key returned by the main-world probe (src/content/probe.js)
//
// Versions feed a small table of known-vulnerable ranges (see VULNERABLE).

export const TECH_RULES = [
  // CMS and site builders
  { name: "WordPress", cat: "CMS", meta: /WordPress\s*([\d.]+)?/i, src: /\/wp-(?:content|includes)\/.*?(?:ver=([\d.]+))?/i, html: /\/wp-(?:content|includes)\//i, global: "wp", cpe: "wordpress:wordpress" },
  { name: "WooCommerce", cat: "E-commerce", meta: /WooCommerce\s*([\d.]+)?/i, src: /\/plugins\/woocommerce\//i, html: /woocommerce/i },
  { name: "Drupal", cat: "CMS", meta: /Drupal\s*([\d.]+)?/i, header: { "x-generator": /Drupal\s*([\d.]+)?/i, "x-drupal-cache": /./ }, src: /\/sites\/(?:default|all)\/|\/core\/misc\/drupal\.js/i, global: "Drupal" },
  { name: "Joomla", cat: "CMS", meta: /Joomla!?\s*([\d.]+)?/i, src: /\/media\/(?:jui|system)\/js\//i, html: /\/components\/com_/i },
  { name: "Ghost", cat: "CMS", meta: /Ghost\s*([\d.]+)?/i, src: /\/ghost\/|ghost\.io/i },
  { name: "TYPO3", cat: "CMS", meta: /TYPO3\s*(?:CMS\s*)?([\d.]+)?/i, src: /\/typo3(?:conf|temp)\//i },
  { name: "Wix", cat: "Site builder", meta: /Wix\.com/i, src: /static\.(?:wixstatic|parastorage)\.com/i, header: { "x-wix-request-id": /./ } },
  { name: "Squarespace", cat: "Site builder", src: /static1?\.squarespace\.com|squarespace-cdn\.com/i, html: /Squarespace\./ },
  { name: "Webflow", cat: "Site builder", meta: /Webflow/i, src: /assets(?:-global)?\.website-files\.com|webflow\.(?:js|com)/i, html: /data-wf-(?:page|site)/i },
  { name: "Framer", cat: "Site builder", meta: /Framer\s*([\w.]+)?/i, src: /framerusercontent\.com|framer\.com\/m\//i },
  { name: "Weebly", cat: "Site builder", src: /editmysite\.com|weebly\.com/i },
  { name: "Duda", cat: "Site builder", src: /dudamobile\.com|multiscreensite\.com|cdn-website\.com/i },
  { name: "HubSpot CMS", cat: "CMS", meta: /HubSpot/i, header: { "x-hs-hub-id": /./ } },
  { name: "Blogger", cat: "CMS", meta: /blogger/i, src: /blogger\.com\/static|bp\.blogspot\.com/i },
  { name: "Medium", cat: "Publishing", src: /cdn-client\.medium\.com/i },
  { name: "Substack", cat: "Publishing", src: /substackcdn\.com/i },
  { name: "Notion", cat: "Site builder", src: /notion\.so|notion-static\.com/i },
  { name: "GitBook", cat: "Documentation", src: /gitbook\.(?:com|io)/i },
  { name: "Docusaurus", cat: "Documentation", meta: /Docusaurus\s*v?([\d.]+)?/i },
  { name: "MkDocs", cat: "Documentation", meta: /mkdocs-([\d.]+)/i },
  { name: "Hugo", cat: "Static site generator", meta: /Hugo\s*([\d.]+)?/i },
  { name: "Jekyll", cat: "Static site generator", meta: /Jekyll\s*v?([\d.]+)?/i },
  { name: "Eleventy", cat: "Static site generator", meta: /Eleventy\s*v?([\d.]+)?/i },
  { name: "Hexo", cat: "Static site generator", meta: /Hexo\s*([\d.]+)?/i },

  // E-commerce
  { name: "Shopify", cat: "E-commerce", src: /cdn\.shopify\.com|\/cdn\/shop\//i, header: { "x-shopid": /./, "x-shopify-stage": /./ }, global: "Shopify", cookie: /^_shopify_/ },
  { name: "Magento", cat: "E-commerce", src: /\/static\/version\d+\/frontend\/|\/skin\/frontend\/|mage\/cookies/i, cookie: /^(?:frontend|mage-cache-sessid)$/, global: "Magento" },
  { name: "PrestaShop", cat: "E-commerce", meta: /PrestaShop/i, src: /\/modules\/ps_|prestashop/i, cookie: /^PrestaShop-/ },
  { name: "BigCommerce", cat: "E-commerce", src: /cdn\d*\.bigcommerce\.com/i },
  { name: "OpenCart", cat: "E-commerce", src: /catalog\/view\/(?:theme|javascript)\//i, cookie: /^OCSESSID$/ },
  { name: "Ecwid", cat: "E-commerce", src: /app\.ecwid\.com/i },

  // JavaScript frameworks and libraries
  { name: "React", cat: "JavaScript framework", global: "React", html: /data-reactroot|data-reactid/i },
  { name: "Next.js", cat: "JavaScript framework", global: "Next.js", html: /\/_next\/static\/|id="__NEXT_DATA__"/i, header: { "x-powered-by": /Next\.js\s*([\d.]+)?/i } },
  { name: "Vue.js", cat: "JavaScript framework", global: "Vue.js", html: /data-v-[0-9a-f]{8}|data-server-rendered/i },
  { name: "Nuxt", cat: "JavaScript framework", global: "Nuxt", html: /\/_nuxt\/|id="__nuxt"|window\.__NUXT__/i },
  { name: "Angular", cat: "JavaScript framework", html: /ng-version="([\d.]+)"/i, global: "Angular" },
  { name: "AngularJS", cat: "JavaScript framework", global: "AngularJS", html: /ng-app=|ng-controller=/i, src: /angular(?:\.min)?\.js|angularjs\/([\d.]+)\//i },
  { name: "Svelte", cat: "JavaScript framework", html: /class="[^"]*svelte-[a-z0-9]{5,}/i, global: "Svelte" },
  { name: "SvelteKit", cat: "JavaScript framework", html: /\/_app\/immutable\/|data-sveltekit/i },
  { name: "Remix", cat: "JavaScript framework", global: "Remix", html: /__remixContext/ },
  { name: "Gatsby", cat: "Static site generator", meta: /Gatsby\s*([\d.]+)?/i, html: /id="___gatsby"/i },
  { name: "Astro", cat: "JavaScript framework", meta: /Astro\s*v?([\d.]+)?/i, html: /astro-island|data-astro-cid/i },
  { name: "Ember.js", cat: "JavaScript framework", global: "Ember.js" },
  { name: "Alpine.js", cat: "JavaScript library", html: /\bx-data=/i, global: "Alpine.js" },
  { name: "htmx", cat: "JavaScript library", html: /\bhx-(?:get|post|target)=/i, global: "htmx" },
  { name: "jQuery", cat: "JavaScript library", global: "jQuery", src: /jquery[.\-]?([\d.]+)?(?:\.min|\.slim)?\.js/i, cpe: "jquery:jquery" },
  { name: "jQuery UI", cat: "JavaScript library", global: "jQuery UI", src: /jquery-ui[.\-]?([\d.]+)?(?:\.min)?\.js/i },
  { name: "Bootstrap", cat: "UI framework", global: "Bootstrap", src: /bootstrap(?:@|[\/.\-])([\d.]+)?.*?\.(?:js|css)/i },
  { name: "Tailwind CSS", cat: "UI framework", html: /class="[^"]*\b(?:flex|grid) [^"]*\b(?:px|py|mt|mb)-\d/ },
  { name: "Font Awesome", cat: "Font", src: /font-?awesome(?:[\/@\-]([\d.]+))?|kit\.fontawesome\.com/i },
  { name: "Google Fonts", cat: "Font", src: /fonts\.(?:googleapis|gstatic)\.com/i },
  { name: "Adobe Fonts", cat: "Font", src: /use\.typekit\.net|p\.typekit\.net/i },
  { name: "Lodash", cat: "JavaScript library", global: "Lodash", src: /lodash(?:\.min)?\.js|lodash@([\d.]+)/i },
  { name: "Moment.js", cat: "JavaScript library", global: "Moment.js", src: /moment(?:\.min)?\.js|moment@([\d.]+)/i },
  { name: "Underscore.js", cat: "JavaScript library", global: "Underscore.js" },
  { name: "core-js", cat: "JavaScript library", global: "core-js" },
  { name: "GSAP", cat: "JavaScript library", global: "GSAP", src: /gsap(?:@|\/)([\d.]+)?/i },
  { name: "Three.js", cat: "JavaScript library", global: "Three.js" },
  { name: "Swiper", cat: "JavaScript library", src: /swiper(?:@|[\/\-])([\d.]+)?.*\.js/i },
  { name: "Modernizr", cat: "JavaScript library", global: "Modernizr", src: /modernizr/i },
  { name: "Polyfill.io", cat: "CDN (compromised 2024)", src: /polyfill\.io\//i },
  { name: "Socket.IO", cat: "JavaScript library", global: "Socket.IO", src: /socket\.io(?:\.min)?\.js/i },
  { name: "Webpack", cat: "Build tool", global: "Webpack" },
  { name: "Vite", cat: "Build tool", html: /\/@vite\/client|type="module" crossorigin src="\/assets\/index-[\w-]+\.js"/i },
  { name: "Turbo / Hotwire", cat: "JavaScript framework", global: "Turbo" },
  { name: "Livewire", cat: "JavaScript framework", global: "Livewire", html: /wire:id=/ },

  // Back-end languages and frameworks (mostly from headers and cookies)
  { name: "PHP", cat: "Language", header: { "x-powered-by": /PHP\/?([\d.]+)?/i }, cookie: /^PHPSESSID$/ },
  { name: "ASP.NET", cat: "Web framework", header: { "x-powered-by": /ASP\.NET/i, "x-aspnet-version": /([\d.]+)/, "x-aspnetmvc-version": /([\d.]+)/ }, cookie: /^ASP\.NET_SessionId$|^\.AspNetCore\./, html: /__VIEWSTATE/ },
  { name: "Java", cat: "Language", cookie: /^JSESSIONID$/ },
  { name: "Express", cat: "Web framework", header: { "x-powered-by": /^Express$/i } },
  { name: "Ruby on Rails", cat: "Web framework", header: { "x-runtime": /^[\d.]+$/ }, html: /csrf-param" content="authenticity_token"/, cookie: /^_[a-z_]+_session$/ },
  { name: "Django", cat: "Web framework", cookie: /^(?:csrftoken|django_language|sessionid)$/, html: /csrfmiddlewaretoken/ },
  { name: "Laravel", cat: "Web framework", cookie: /^(?:laravel_session|XSRF-TOKEN)$/ },
  { name: "Flask", cat: "Web framework", header: { server: /Werkzeug\/?([\d.]+)?/i } },
  { name: "Phoenix", cat: "Web framework", html: /data-phx-main|phx-click/ },
  { name: "Craft CMS", cat: "CMS", header: { "x-powered-by": /Craft CMS/i }, cookie: /^CraftSessionId$/ },
  { name: "Strapi", cat: "Headless CMS", header: { "x-powered-by": /Strapi/i } },
  { name: "Contentful", cat: "Headless CMS", src: /ctfassets\.net/i },
  { name: "Sanity", cat: "Headless CMS", src: /cdn\.sanity\.io/i },
  { name: "Prismic", cat: "Headless CMS", src: /prismic\.io/i },

  // Servers, CDNs, hosting, WAF
  { name: "Nginx", cat: "Web server", header: { server: /nginx\/?([\d.]+)?/i }, cpe: "nginx:nginx" },
  { name: "Apache HTTP Server", cat: "Web server", header: { server: /Apache\/?([\d.]+)?/i }, cpe: "apache:http_server" },
  { name: "Microsoft IIS", cat: "Web server", header: { server: /Microsoft-IIS\/?([\d.]+)?/i }, cpe: "microsoft:internet_information_services" },
  { name: "LiteSpeed", cat: "Web server", header: { server: /LiteSpeed/i } },
  { name: "Caddy", cat: "Web server", header: { server: /Caddy/i } },
  { name: "OpenResty", cat: "Web server", header: { server: /openresty\/?([\d.]+)?/i } },
  { name: "Envoy", cat: "Proxy", header: { server: /envoy/i, "x-envoy-upstream-service-time": /./ } },
  { name: "Varnish", cat: "Cache", header: { via: /varnish/i, "x-varnish": /./ } },
  { name: "Cloudflare", cat: "CDN / WAF", header: { server: /cloudflare/i, "cf-ray": /./, "cf-cache-status": /./ }, src: /cdnjs\.cloudflare\.com|\/cdn-cgi\//i },
  { name: "Akamai", cat: "CDN", header: { "x-akamai-transformed": /./, server: /AkamaiGHost|AkamaiNetStorage/i, "akamai-grn": /./ } },
  { name: "Fastly", cat: "CDN", header: { "x-served-by": /cache-[a-z]{3}/i, "fastly-debug-digest": /./, "x-fastly-request-id": /./ } },
  { name: "Amazon CloudFront", cat: "CDN", header: { via: /CloudFront/i, "x-amz-cf-id": /./, "x-amz-cf-pop": /./ } },
  { name: "Amazon S3", cat: "Hosting", header: { server: /AmazonS3/i, "x-amz-request-id": /./ } },
  { name: "Google Cloud", cat: "Hosting", header: { server: /^(?:gws|Google Frontend|ESF)$/i, via: /1\.1 google/i } },
  { name: "Microsoft Azure", cat: "Hosting", header: { "x-azure-ref": /./, "x-ms-request-id": /./ } },
  { name: "Vercel", cat: "Hosting", header: { server: /Vercel/i, "x-vercel-id": /./, "x-vercel-cache": /./ } },
  { name: "Netlify", cat: "Hosting", header: { server: /Netlify/i, "x-nf-request-id": /./ } },
  { name: "GitHub Pages", cat: "Hosting", header: { server: /GitHub\.com/i, "x-github-request-id": /./ } },
  { name: "Heroku", cat: "Hosting", header: { via: /vegur/i } },
  { name: "Fly.io", cat: "Hosting", header: { server: /Fly\/[\w]+/i, "fly-request-id": /./ } },
  { name: "Render", cat: "Hosting", header: { "x-render-origin-server": /./, "rndr-id": /./ } },
  { name: "Firebase Hosting", cat: "Hosting", header: { "x-firebase-hosting": /./ }, src: /\/__\/firebase\// },
  { name: "Sucuri", cat: "WAF", header: { server: /Sucuri/i, "x-sucuri-id": /./ } },
  { name: "Imperva / Incapsula", cat: "WAF", header: { "x-iinfo": /./, "x-cdn": /Incapsula|Imperva/i }, cookie: /^(?:incap_ses_|visid_incap_)/ },
  { name: "DDoS-Guard", cat: "WAF", header: { server: /ddos-guard/i } },
  { name: "Wordfence", cat: "WAF", src: /wordfence/i },
  { name: "jsDelivr", cat: "CDN", src: /cdn\.jsdelivr\.net/i },
  { name: "unpkg", cat: "CDN", src: /unpkg\.com/i },
  { name: "cdnjs", cat: "CDN", src: /cdnjs\.cloudflare\.com/i },

  // Analytics, ads and marketing (overlaps trackers.js, which extracts the IDs)
  { name: "Google Analytics", cat: "Analytics", src: /google-analytics\.com\/(?:analytics|ga)\.js|googletagmanager\.com\/gtag\/js/i, global: "Google Analytics", cookie: /^_ga(?:_|$)/ },
  { name: "Google Tag Manager", cat: "Tag manager", src: /googletagmanager\.com\/gtm\.js/i, global: "Google Tag Manager" },
  { name: "Meta Pixel", cat: "Advertising", src: /connect\.facebook\.net\/[^/]+\/fbevents\.js/i, global: "Meta Pixel", cookie: /^_fbp$/ },
  { name: "Hotjar", cat: "Session replay", src: /static\.hotjar\.com/i, cookie: /^_hj/ },
  { name: "Microsoft Clarity", cat: "Session replay", src: /clarity\.ms/i, cookie: /^_clck$|^_clsk$/ },
  { name: "Matomo", cat: "Analytics", src: /matomo\.js|piwik\.js/i, global: "Matomo" },
  { name: "Plausible", cat: "Analytics", src: /plausible\.io\/js/i },
  { name: "Fathom", cat: "Analytics", src: /cdn\.usefathom\.com/i },
  { name: "Umami", cat: "Analytics", src: /umami\.(?:is|js)|\/umami\.js/i },
  { name: "Segment", cat: "Customer data platform", src: /cdn\.segment\.com/i },
  { name: "HubSpot", cat: "Marketing automation", src: /js\.hs-scripts\.com|js\.hsforms\.net|js\.hs-analytics\.net/i },
  { name: "Intercom", cat: "Live chat", src: /widget\.intercom\.io|js\.intercomcdn\.com/i },
  { name: "Zendesk", cat: "Live chat", src: /static\.zdassets\.com/i },
  { name: "Cookiebot", cat: "Consent management", src: /consent\.cookiebot\.com/i },
  { name: "OneTrust", cat: "Consent management", src: /cdn\.cookielaw\.org|onetrust\.com/i },
  { name: "Sentry", cat: "Error monitoring", src: /browser\.sentry-cdn\.com|js\.sentry-cdn\.com/i, global: "Sentry" },
  { name: "New Relic", cat: "Monitoring", src: /js-agent\.newrelic\.com/i, global: "New Relic" },
  { name: "Datadog RUM", cat: "Monitoring", src: /datadoghq-browser-agent\.com/i, global: "Datadog RUM" },
  { name: "Stripe", cat: "Payments", src: /js\.stripe\.com/i, global: "Stripe" },
  { name: "PayPal", cat: "Payments", src: /paypal\.com\/sdk\/js|paypalobjects\.com/i },
  { name: "reCAPTCHA", cat: "Security", src: /google\.com\/recaptcha|gstatic\.com\/recaptcha|recaptcha\.net/i },
  { name: "hCaptcha", cat: "Security", src: /hcaptcha\.com/i },
  { name: "Cloudflare Turnstile", cat: "Security", src: /challenges\.cloudflare\.com\/turnstile/i },
  { name: "Google Maps", cat: "Maps", src: /maps\.googleapis\.com|maps\.google\.com\/maps\/api/i },
  { name: "Mapbox", cat: "Maps", src: /api\.mapbox\.com|mapbox-gl/i },
  { name: "Leaflet", cat: "Maps", global: "Leaflet", src: /leaflet(?:@([\d.]+))?/i },
  { name: "YouTube embed", cat: "Video", src: /youtube(?:-nocookie)?\.com\/(?:embed|iframe_api)/i },
  { name: "Vimeo embed", cat: "Video", src: /player\.vimeo\.com/i },
  { name: "Firebase", cat: "Backend", src: /firebasejs|firebaseio\.com|gstatic\.com\/firebasejs\/([\d.]+)/i, global: "Firebase" },
  { name: "Supabase", cat: "Backend", src: /supabase\.co/i },
  { name: "Auth0", cat: "Identity", src: /cdn\.auth0\.com|auth0\.com/i },
  { name: "Okta", cat: "Identity", src: /okta(?:cdn)?\.com/i },
  { name: "Algolia", cat: "Search", src: /algolia(?:net)?\.(?:com|net)|algoliasearch/i },
  { name: "Web3 / wallet connect", cat: "Crypto", src: /walletconnect|web3modal|ethers(?:\.umd)?(?:\.min)?\.js|web3(?:\.min)?\.js|wagmi|reown/i, global: "Web3 wallet" },
  { name: "PWA (service worker)", cat: "Platform", global: "Service worker" }
];

/**
 * Known-vulnerable version ranges for common front-end libraries and servers.
 * Deliberately short and conservative; it flags clearly outdated versions,
 * it is not a full vulnerability database. Each: [tech, belowVersion, summary, ids]
 */
export const VULNERABLE = [
  ["jQuery", "1.9.0", "XSS via $(html) selector parsing", ["CVE-2012-6708"]],
  ["jQuery", "3.0.0", "XSS in cross-domain AJAX responses", ["CVE-2015-9251"]],
  ["jQuery", "3.4.0", "Prototype pollution in jQuery.extend", ["CVE-2019-11358"]],
  ["jQuery", "3.5.0", "XSS in htmlPrefilter (.html(), .append())", ["CVE-2020-11022", "CVE-2020-11023"]],
  ["jQuery UI", "1.13.2", "XSS in several widget options", ["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184", "CVE-2022-31160"]],
  ["Bootstrap", "3.4.1", "XSS in tooltip/popover data attributes", ["CVE-2018-14040", "CVE-2018-14042", "CVE-2019-8331"]],
  ["Bootstrap", "4.3.1", "XSS in tooltip/popover sanitizer", ["CVE-2019-8331"]],
  ["AngularJS", "1.8.4", "End of life since 2022; multiple unpatched XSS/ReDoS issues", ["CVE-2022-25869", "CVE-2023-26116"]],
  ["Lodash", "4.17.21", "Prototype pollution / command injection in template", ["CVE-2020-8203", "CVE-2021-23337"]],
  ["Moment.js", "2.29.4", "ReDoS and path traversal", ["CVE-2022-24785", "CVE-2022-31129"]],
  ["Underscore.js", "1.13.0", "Arbitrary code execution in template", ["CVE-2021-23358"]],
  ["Handlebars", "4.7.7", "Prototype pollution / RCE in templates", ["CVE-2021-23369"]],
  ["Next.js", "14.2.25", "Middleware authorization bypass (x-middleware-subrequest)", ["CVE-2025-29927"]],
  ["Nginx", "1.20.1", "1-byte memory overwrite in resolver", ["CVE-2021-23017"]],
  ["Apache HTTP Server", "2.4.62", "Multiple vulnerabilities fixed in 2.4.62+", ["CVE-2024-38475", "CVE-2024-38476"]],
  ["PHP", "8.1.0", "PHP branch no longer receives security fixes", []],
  ["Microsoft IIS", "8.5", "Very old IIS (Windows Server 2012 R2 or earlier)", []],
  ["WordPress", "6.4.2", "Core security fixes in later releases", ["CVE-2023-5561"]],
  ["Drupal", "10.1.8", "Security fixes in later releases", []]
];

/** Compare dotted versions: -1, 0, 1. Non-numeric parts are ignored. */
export function cmpVersion(a, b) {
  const pa = String(a).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Detect technologies.
 * @param {object} s
 * @param {string}   [s.html]       page HTML (or a prefix of it)
 * @param {string[]} [s.urls]       script, stylesheet and resource URLs
 * @param {string}   [s.generator]  meta generator content
 * @param {Object<string,string>} [s.headers] response headers (lowercase keys)
 * @param {string[]} [s.cookies]    cookie names
 * @param {Object<string,string|true>} [s.globals] main-world probe results: name -> version|true
 * @returns {Array<{name,cat,version,evidence:string[],vulns:Array}>}
 */
export function detectTech(s) {
  const found = new Map();
  const hit = (rule, evidence, version) => {
    let t = found.get(rule.name);
    if (!t) {
      t = { name: rule.name, cat: rule.cat, version: null, evidence: [], cpe: rule.cpe || null, vulns: [] };
      found.set(rule.name, t);
    }
    if (version && /\d/.test(version) && (!t.version || version.length > t.version.length)) t.version = version.replace(/^v/, "");
    if (!t.evidence.includes(evidence)) t.evidence.push(evidence);
  };
  const headers = s.headers || {};
  const urls = s.urls || [];
  const cookies = s.cookies || [];
  const globals = s.globals || {};

  for (const r of TECH_RULES) {
    if (r.meta && s.generator) {
      const m = r.meta.exec(s.generator);
      if (m) hit(r, `generator: ${s.generator}`, m[1]);
    }
    if (r.src) {
      for (const u of urls) {
        const m = r.src.exec(u);
        if (m) {
          hit(r, `resource: ${u.length > 90 ? `${u.slice(0, 90)}…` : u}`, m[1]);
          if (m[1]) break;
        }
      }
    }
    if (r.html && s.html) {
      const m = r.html.exec(s.html);
      if (m) hit(r, "page markup", m[1]);
    }
    if (r.header) {
      for (const [name, re] of Object.entries(r.header)) {
        const v = headers[name];
        if (v == null) continue;
        const m = re.exec(v);
        if (m) hit(r, `header ${name}: ${v}`, m[1]);
      }
    }
    if (r.cookie) {
      const c = cookies.find((n) => r.cookie.test(n));
      if (c) hit(r, `cookie: ${c}`);
    }
    if (r.global && globals[r.global] !== undefined) {
      const v = globals[r.global];
      hit(r, "JavaScript runtime", typeof v === "string" ? v : null);
    }
  }

  for (const t of found.values()) {
    if (!t.version) continue;
    for (const [name, below, summary, ids] of VULNERABLE) {
      if (name === t.name && cmpVersion(t.version, below) < 0) t.vulns.push({ below, summary, ids });
    }
  }
  if (found.has("Polyfill.io")) {
    found.get("Polyfill.io").vulns.push({ below: "*", summary: "polyfill.io was taken over in 2024 and served malware; remove it", ids: [] });
  }
  return [...found.values()].sort((a, b) => b.vulns.length - a.vulns.length || a.cat.localeCompare(b.cat) || a.name.localeCompare(b.name));
}
