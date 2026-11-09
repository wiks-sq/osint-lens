// Functions injected into the inspected page with chrome.scripting.executeScript.
//
// Chrome serialises each function and runs it in the page, so every function
// here must be self-contained: no imports and no references to anything
// outside its own body. They run in the extension's isolated world (the page's
// own scripts can't see or tamper with them), except probeMainWorld, which has
// to run in the page's main world to read JavaScript globals.

/**
 * Read everything the analysis needs from the DOM.
 * @param {{includeFormValues:boolean, maxHtml:number, maxText:number}} opts
 */
export function collectPage(opts) {
  const o = Object.assign({ includeFormValues: false, maxHtml: 3_000_000, maxText: 1_000_000 }, opts || {});
  const abs = (u) => {
    try {
      return new URL(u, document.baseURI).href;
    } catch {
      return null;
    }
  };
  const txt = (s, n = 200) => String(s || "").replace(/\s+/g, " ").trim().slice(0, n);
  const cap = (arr, n) => (arr.length > n ? arr.slice(0, n) : arr);

  // --- Meta and link tags ----------------------------------------------------
  const meta = [...document.querySelectorAll("meta")].map((m) => ({
    name: (m.getAttribute("name") || "").toLowerCase(),
    property: (m.getAttribute("property") || "").toLowerCase(),
    httpEquiv: (m.getAttribute("http-equiv") || "").toLowerCase(),
    itemprop: m.getAttribute("itemprop") || "",
    charset: m.getAttribute("charset") || "",
    content: (m.getAttribute("content") || "").slice(0, 2000)
  })).filter((m) => m.content || m.charset);

  const linkTags = cap([...document.querySelectorAll("link[href]")].map((l) => ({
    rel: (l.getAttribute("rel") || "").toLowerCase(),
    href: abs(l.getAttribute("href")),
    type: l.getAttribute("type") || "",
    sizes: l.getAttribute("sizes") || "",
    hreflang: l.getAttribute("hreflang") || "",
    title: l.getAttribute("title") || ""
  })).filter((l) => l.href), 500);

  // --- Links (including open shadow roots and same-origin iframes) ----------
  const roots = [document];
  const walkShadow = (root) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) {
        roots.push(el.shadowRoot);
        walkShadow(el.shadowRoot);
      }
    }
  };
  try {
    walkShadow(document);
  } catch {
    /* very large DOMs: keep what we have */
  }
  let sameOriginFrames = 0;
  let crossOriginFrames = 0;
  for (const f of document.querySelectorAll("iframe, frame")) {
    try {
      if (f.contentDocument?.documentElement) {
        roots.push(f.contentDocument);
        sameOriginFrames++;
      } else crossOriginFrames++;
    } catch {
      crossOriginFrames++;
    }
  }

  const links = [];
  const seen = new Set();
  for (const root of roots) {
    for (const a of root.querySelectorAll("a[href], area[href]")) {
      let href;
      try {
        href = typeof a.href === "string" ? a.href : new URL(a.getAttribute("href"), document.baseURI).href;
      } catch {
        continue;
      }
      if (!href || /^javascript:/i.test(href) || seen.has(href)) continue;
      seen.add(href);
      links.push({ href, text: txt(a.innerText || a.getAttribute("aria-label") || a.getAttribute("title") || a.querySelector("img")?.alt || "", 160), rel: a.getAttribute("rel") || "" });
      if (links.length >= 5000) break;
    }
  }

  // --- Scripts ---------------------------------------------------------------------
  let inlineBudget = 2_500_000;
  const scripts = [];
  const jsonld = [];
  for (const s of document.querySelectorAll("script")) {
    const type = (s.getAttribute("type") || "").toLowerCase();
    if (type === "application/ld+json") {
      jsonld.push(s.textContent.slice(0, 200_000));
      continue;
    }
    const src = s.getAttribute("src");
    const entry = { src: src ? abs(src) : null, type, async: s.async, defer: s.defer, integrity: s.getAttribute("integrity") || "", crossorigin: s.getAttribute("crossorigin") || "", nonce: !!s.nonce };
    if (!src) {
      const t = s.textContent || "";
      entry.length = t.length;
      if (inlineBudget > 0) {
        entry.text = t.slice(0, Math.min(300_000, inlineBudget));
        inlineBudget -= entry.text.length;
      }
    }
    scripts.push(entry);
    if (scripts.length >= 600) break;
  }

  const styles = cap([...document.querySelectorAll('link[rel~="stylesheet"][href]')].map((l) => abs(l.getAttribute("href"))).filter(Boolean), 300);
  const iframes = cap([...document.querySelectorAll("iframe, frame, embed, object")].map((f) => {
    const r = f.getBoundingClientRect();
    return { src: abs(f.getAttribute("src") || f.getAttribute("data") || "") || "", title: f.getAttribute("title") || "", sandbox: f.getAttribute("sandbox"), w: Math.round(r.width), h: Math.round(r.height), tag: f.tagName.toLowerCase() };
  }), 200);

  const images = [];
  const seenImg = new Set();
  for (const img of document.querySelectorAll("img, picture source, image, [style*='background-image']")) {
    let src = img.currentSrc || img.getAttribute("src") || img.getAttribute("href") || img.getAttribute("xlink:href") || "";
    if (!src && img.getAttribute("srcset")) src = img.getAttribute("srcset").split(",").pop().trim().split(/\s+/)[0];
    if (!src && img.style?.backgroundImage) src = (/url\(["']?([^"')]+)/.exec(img.style.backgroundImage) || [])[1] || "";
    const u = src && abs(src);
    if (!u || seenImg.has(u) || /^data:image\/svg/.test(u)) continue;
    seenImg.add(u);
    images.push({ src: u.startsWith("data:") ? u.slice(0, 80) : u, alt: txt(img.getAttribute("alt"), 120), w: img.naturalWidth || 0, h: img.naturalHeight || 0, data: u.startsWith("data:") });
    if (images.length >= 600) break;
  }
  const media = cap([...document.querySelectorAll("video[src], audio[src], video source[src], audio source[src], track[src]")].map((m) => abs(m.getAttribute("src"))).filter(Boolean), 100);

  // --- Forms -----------------------------------------------------------------------------
  const labelFor = (el) => txt(el.labels?.[0]?.innerText || el.getAttribute("aria-label") || el.getAttribute("placeholder") || el.name || el.id || "", 80);
  const forms = [];
  const formEls = new Set(document.querySelectorAll("form"));
  // Inputs outside any <form> (common in JS-driven login pages) are grouped as a virtual form.
  const orphanInputs = [...document.querySelectorAll("input, textarea, select")].filter((i) => !i.form);
  const groups = [...formEls].map((f) => ({ el: f, inputs: [...f.querySelectorAll("input, textarea, select")] }));
  if (orphanInputs.length) groups.push({ el: null, inputs: orphanInputs });
  for (const g of cap(groups, 100)) {
    const fields = [];
    let hasPassword = false, hasEmail = false, hasCard = false, hidden = 0, textareas = 0;
    const hiddenFields = [];
    for (const i of g.inputs) {
      const type = (i.type || i.tagName).toLowerCase();
      const name = (i.name || i.id || "").slice(0, 80);
      const ac = (i.getAttribute("autocomplete") || "").toLowerCase();
      if (type === "password") hasPassword = true;
      if (type === "email" || /e-?mail|username|login|user_?id/i.test(name + ac)) hasEmail = true;
      if (/cc-|card|cvv|cvc|expir|ccnum|cardnumber/i.test(name + ac + (i.placeholder || ""))) hasCard = true;
      if (i.tagName === "TEXTAREA") textareas++;
      if (type === "hidden") {
        hidden++;
        hiddenFields.push({ name, length: (i.value || "").length, value: (i.value || "").slice(0, 300) });
        continue;
      }
      if (/^(submit|button|reset|image)$/.test(type)) continue;
      const f = { type, name, autocomplete: ac, label: labelFor(i), required: i.required };
      if (o.includeFormValues && type !== "password" && !/^(checkbox|radio|file)$/.test(type) && i.value) f.value = String(i.value).slice(0, 500);
      if (type === "password" && i.value) f.filled = true;
      fields.push(f);
    }
    if (!fields.length && !hidden) continue;
    forms.push({
      virtual: !g.el,
      action: g.el ? (g.el.getAttribute("action") ? abs(g.el.getAttribute("action")) : location.href) : null,
      rawAction: g.el?.getAttribute("action") || "",
      method: (g.el?.getAttribute("method") || "get").toLowerCase(),
      id: g.el?.id || "",
      name: g.el?.getAttribute("name") || "",
      autocompleteOff: g.el?.getAttribute("autocomplete") === "off",
      hasPassword, hasEmail, hasCard, hidden, textareas,
      inputs: fields.length,
      fields: cap(fields, 60),
      hiddenFields: cap(hiddenFields, 40)
    });
  }

  // --- Comments -----------------------------------------------------------------------------
  const comments = [];
  try {
    const it = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT);
    for (let n; (n = it.nextNode()) && comments.length < 400; ) {
      const t = (n.nodeValue || "").trim();
      if (t) comments.push(t.slice(0, 2000));
    }
  } catch {
    /* ignore */
  }

  // --- Text -----------------------------------------------------------------------------------
  const bodyText = (document.body?.innerText || "").slice(0, o.maxText);
  let shadowText = "";
  for (const r of roots.slice(1)) {
    if (r instanceof Document) shadowText += `\n${(r.body?.innerText || "").slice(0, 200_000)}`;
    else shadowText += `\n${(r.textContent || "").slice(0, 100_000)}`;
    if (shadowText.length > 500_000) break;
  }
  // Text present in the DOM but not rendered (display:none menus, hidden divs, noscript...).
  const allText = (document.body?.textContent || "").replace(/\s+/g, " ");
  const hiddenTextLength = Math.max(0, allText.length - bodyText.replace(/\s+/g, " ").length);

  // --- Network resources the page loaded ---------------------------------------------------------
  let resources = [];
  try {
    resources = cap(performance.getEntriesByType("resource").map((e) => ({ url: e.name, kind: e.initiatorType, size: e.transferSize || e.encodedBodySize || 0, serverTiming: (e.serverTiming || []).map((s) => `${s.name}${s.description ? `;desc=${s.description}` : ""}${s.duration ? `;dur=${s.duration}` : ""}`) })), 2500);
  } catch {
    /* ignore */
  }
  let navigation = null;
  try {
    const n = performance.getEntriesByType("navigation")[0];
    if (n) navigation = { type: n.type, protocol: n.nextHopProtocol, serverTiming: (n.serverTiming || []).map((s) => `${s.name}${s.description ? `;desc=${s.description}` : ""}`), redirectCount: n.redirectCount, transferSize: n.transferSize, ttfb: Math.round(n.responseStart - n.requestStart) };
  } catch {
    /* ignore */
  }

  // --- Storage (names only, never values) -------------------------------------------------------------
  const cookies = document.cookie ? document.cookie.split(";").map((c) => c.split("=")[0].trim()).filter(Boolean) : [];
  const keys = (s) => {
    try {
      return Object.keys(s).slice(0, 200);
    } catch {
      return [];
    }
  };

  // --- Behavioural flags (phishing/scam heuristics) ----------------------------------------------------
  const html = document.documentElement.outerHTML;
  const inline = scripts.filter((s) => s.text).map((s) => s.text).join("\n");
  const flags = {};
  if (/oncontextmenu\s*=\s*["']?\s*return\s+false|addEventListener\(\s*["']contextmenu["'][\s\S]{0,120}preventDefault|onselectstart\s*=\s*["']?\s*return\s+false/i.test(html)) flags.rightClickBlocked = true;
  if (/devtools(?:change|open|detect)|(?:outer|inner)(?:Width|Height)\s*-\s*window\.(?:inner|outer)(?:Width|Height)\s*>\s*\d{2,3}|setInterval\(\s*(?:function\s*\(\)\s*\{\s*)?debugger/i.test(inline)) flags.devtoolsDetect = true;
  const obf = [];
  if (/eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/.test(inline)) obf.push("eval of decoded string");
  if (/eval\(function\(p,a,c,k,e,[dr]\)/.test(inline)) obf.push("packer");
  if ((inline.match(/_0x[a-f0-9]{4,6}/g) || []).length > 80) obf.push("javascript-obfuscator identifiers");
  if ((inline.match(/\\x[0-9a-f]{2}/gi) || []).length > 400) obf.push("hex-escaped strings");
  if (/document\.write\s*\(\s*(?:unescape|atob|decodeURIComponent)\s*\(/.test(inline)) obf.push("document.write of decoded HTML");
  if (obf.length) flags.obfuscated = obf.join(", ");
  const refresh = meta.find((m) => m.httpEquiv === "refresh");
  if (refresh) flags.metaRefresh = refresh.content.slice(0, 200);
  const vw = innerWidth, vh = innerHeight;
  const big = iframes.find((f) => f.w >= vw * 0.9 && f.h >= vh * 0.85 && f.src && !f.src.startsWith(location.origin));
  if (big) flags.fullPageIframe = big.src.slice(0, 200);
  if (meta.some((m) => m.name === "robots" && /noindex/i.test(m.content))) flags.noIndex = true;
  if (/walletconnect|web3modal|ethereum\.request\(\s*\{\s*method\s*:\s*["']eth_requestAccounts|window\.ethereum|solana\.connect\(|reown/i.test(html)) flags.walletConnect = true;
  if (/navigator\.clipboard\.writeText|execCommand\(\s*["']copy["']\s*\)/.test(inline)) flags.clipboardWrite = true;

  // --- Favicon candidates ----------------------------------------------------------------------------------
  const favicons = linkTags.filter((l) => /(?:^|\s)(?:icon|shortcut icon|apple-touch-icon|mask-icon)(?:\s|$)/.test(l.rel)).map((l) => l.href);
  favicons.push(new URL("/favicon.ico", location.origin).href);

  return {
    url: location.href,
    origin: location.origin,
    title: document.title,
    referrer: document.referrer,
    lang: document.documentElement.lang || "",
    dir: document.dir || "",
    charset: document.characterSet,
    contentType: document.contentType,
    doctype: document.doctype ? `<!DOCTYPE ${document.doctype.name}${document.doctype.publicId ? ` PUBLIC "${document.doctype.publicId}"` : ""}>` : "",
    lastModified: document.lastModified,
    html: html.slice(0, o.maxHtml),
    htmlLength: html.length,
    text: bodyText,
    shadowText: shadowText.slice(0, 500_000),
    hiddenTextLength,
    meta,
    linkTags,
    links,
    scripts,
    jsonld,
    styles,
    iframes,
    images,
    media,
    forms,
    comments,
    resources,
    navigation,
    cookies,
    storage: { local: keys(localStorage), session: keys(sessionStorage) },
    flags,
    favicons: [...new Set(favicons)],
    frames: { sameOrigin: sameOriginFrames, crossOrigin: crossOriginFrames },
    shadowRoots: roots.filter((r) => !(r instanceof Document)).length,
    elementCount: document.getElementsByTagName("*").length,
    collectedAt: new Date().toISOString()
  };
}

/**
 * Runs in the page's MAIN world: reads framework globals and tag-manager state
 * that only exist as JavaScript objects. Returns small, JSON-safe values.
 */
export function probeMainWorld() {
  const w = window;
  const g = {};
  const ver = (v) => (typeof v === "string" && v.length < 40 ? v : true);
  const tryGet = (fn) => {
    try {
      return fn();
    } catch {
      return undefined;
    }
  };
  const set = (name, fn) => {
    const v = tryGet(fn);
    if (v !== undefined && v !== null && v !== false) g[name] = ver(v);
  };
  set("jQuery", () => w.jQuery?.fn?.jquery || (w.$?.fn?.jquery));
  set("jQuery UI", () => w.jQuery?.ui?.version);
  set("React", () => w.React?.version || (w.__REACT_DEVTOOLS_GLOBAL_HOOK__?.renderers?.size ? [...w.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.values()][0]?.version || true : undefined) || (document.querySelector("[data-reactroot], #__next, #root")?._reactRootContainer ? true : undefined));
  set("Next.js", () => w.next?.version || (w.__NEXT_DATA__ ? true : undefined));
  set("Vue.js", () => w.Vue?.version || (w.__VUE__ ? true : undefined) || document.querySelector("[data-v-app]")?.__vue_app__?.version);
  set("Nuxt", () => (w.__NUXT__ || w.$nuxt ? true : undefined));
  set("Angular", () => w.getAllAngularRootElements?.()[0]?.getAttribute("ng-version") || (w.ng ? true : undefined));
  set("AngularJS", () => w.angular?.version?.full);
  set("Svelte", () => (w.__svelte ? true : undefined));
  set("Remix", () => (w.__remixContext ? true : undefined));
  set("Ember.js", () => w.Ember?.VERSION);
  set("Alpine.js", () => w.Alpine?.version);
  set("htmx", () => w.htmx?.version);
  set("Bootstrap", () => w.bootstrap?.Tooltip?.VERSION || w.jQuery?.fn?.tooltip?.Constructor?.VERSION);
  set("Lodash", () => (w._?.VERSION && typeof w._.chunk === "function" ? w._.VERSION : undefined));
  set("Underscore.js", () => (w._?.VERSION && typeof w._.chunk !== "function" ? w._.VERSION : undefined));
  set("Moment.js", () => w.moment?.version);
  set("core-js", () => w.core?.version || w.__core_js_shared__?.versions?.[0]?.version);
  set("GSAP", () => w.gsap?.version);
  set("Three.js", () => w.THREE?.REVISION);
  set("Socket.IO", () => w.io?.version || (w.io?.Socket ? true : undefined));
  set("Leaflet", () => w.L?.version);
  set("Modernizr", () => w.Modernizr?._version);
  set("Webpack", () => (w.webpackJsonp || Object.keys(w).some((k) => /^webpackChunk/.test(k)) ? true : undefined));
  set("Turbo", () => (w.Turbo ? true : undefined));
  set("Livewire", () => (w.Livewire ? true : undefined));
  set("Drupal", () => (w.Drupal ? true : undefined));
  set("wp", () => (w.wp || w.wpApiSettings ? true : undefined));
  set("Shopify", () => (w.Shopify ? true : undefined));
  set("Magento", () => (w.Mage || w.require?.s?.contexts?._?.config?.paths?.mage ? true : undefined));
  set("Google Analytics", () => (w.gtag || w.ga || w.GoogleAnalyticsObject ? true : undefined));
  set("Google Tag Manager", () => (w.google_tag_manager ? true : undefined));
  set("Meta Pixel", () => w.fbq?.version);
  set("Matomo", () => (w._paq || w.Matomo || w.Piwik ? true : undefined));
  set("Sentry", () => w.Sentry?.SDK_VERSION || (w.__SENTRY__ ? true : undefined));
  set("New Relic", () => (w.NREUM || w.newrelic ? true : undefined));
  set("Datadog RUM", () => (w.DD_RUM ? w.DD_RUM.version || true : undefined));
  set("Stripe", () => (w.Stripe ? w.Stripe.version || true : undefined));
  set("Firebase", () => w.firebase?.SDK_VERSION);
  set("Web3 wallet", () => (w.ethereum || w.web3 || w.solana ? true : undefined));
  set("Service worker", () => (navigator.serviceWorker?.controller ? true : undefined));

  // IDs loaded at runtime: GTM containers and every tag ID they configured.
  const ids = new Set();
  tryGet(() => Object.keys(w.google_tag_manager || {}).filter((k) => /^(GTM|G|UA|AW|DC|GT)-/.test(k)).forEach((k) => ids.add(k)));
  tryGet(() => (w.dataLayer || []).slice(0, 300).forEach((e) => {
    const s = JSON.stringify(e) || "";
    for (const m of s.matchAll(/\b(?:G|UA|AW|GTM|DC)-[A-Z0-9\-]{4,14}\b/g)) ids.add(m[0]);
  }));
  tryGet(() => w.ga?.getAll?.().forEach((t) => ids.add(t.get("trackingId"))));
  tryGet(() => w.fbq?.getState?.().pixels?.forEach((p) => ids.add(`fbpixel:${p.id}`)));

  // Build-time config objects that frequently carry API keys and endpoints.
  const configs = {};
  for (const k of ["__NEXT_DATA__", "__NUXT__", "__APOLLO_STATE__", "__INITIAL_STATE__", "__PRELOADED_STATE__", "_env_", "__ENV__", "env", "APP_CONFIG", "appConfig", "__CONFIG__", "config", "firebaseConfig", "__remixContext", "Shopify", "wpApiSettings", "drupalSettings"]) {
    const v = tryGet(() => w[k]);
    if (!v || typeof v !== "object") continue;
    let s = tryGet(() => JSON.stringify(k === "__NEXT_DATA__" ? { buildId: v.buildId, runtimeConfig: v.runtimeConfig, page: v.page, assetPrefix: v.assetPrefix, props: v.props?.pageProps ? Object.keys(v.props.pageProps) : undefined } : v));
    if (s) configs[k] = s.slice(0, 20000);
  }
  return { globals: g, runtimeIds: [...ids].filter(Boolean).slice(0, 200), configs };
}

/**
 * Fetch URLs from inside the page (same-origin requests carry no CORS limits,
 * which lets us read the page's own response headers, robots.txt, etc.).
 * @param {Array<{url:string, binary?:boolean, maxBytes?:number, method?:string}>} reqs
 */
export async function pageFetch(reqs) {
  const out = [];
  const toB64 = (u8) => {
    let s = "";
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  };
  await Promise.all(reqs.map(async (r, i) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), r.timeoutMs || 15000);
    try {
      const res = await fetch(r.url, { method: r.method || "GET", credentials: "same-origin", cache: "no-store", redirect: "follow", signal: ctrl.signal });
      const headers = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      const max = r.maxBytes || 2_000_000;
      let bytes = new Uint8Array(0);
      if (r.method !== "HEAD" && res.body) {
        const reader = res.body.getReader();
        const chunks = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          total += value.length;
          if (total >= max) {
            reader.cancel().catch(() => {});
            break;
          }
        }
        bytes = new Uint8Array(Math.min(total, max));
        let p = 0;
        for (const c of chunks) {
          const n = Math.min(c.length, bytes.length - p);
          bytes.set(c.subarray(0, n), p);
          p += n;
          if (p >= bytes.length) break;
        }
      }
      out[i] = {
        url: r.url,
        finalUrl: res.url,
        redirected: res.redirected,
        ok: res.ok,
        status: res.status,
        headers,
        size: bytes.length,
        truncated: bytes.length >= max,
        text: r.binary ? undefined : new TextDecoder().decode(bytes),
        b64: r.binary ? toB64(bytes) : undefined
      };
    } catch (e) {
      out[i] = { url: r.url, ok: false, status: 0, error: e.name === "AbortError" ? "timeout" : String(e.message || e) };
    } finally {
      clearTimeout(timer);
    }
  }));
  return out;
}
