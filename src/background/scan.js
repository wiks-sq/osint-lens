// The page scan: collect from the page, fetch the site's public well-known
// files and scripts, analyse, store.

import { collectPage, probeMainWorld, pageFetch } from "../content/collect.js";
import { buildReport } from "../core/analyze.js";
import { faviconHashes } from "../core/favicon.js";
import { parseRobots } from "../core/wellknown.js";
import { base64ToBytes } from "../core/util.js";
import { putReport, correlate, pruneReports } from "../shared/db.js";
import { getSettings, newId } from "../shared/settings.js";
import { setTabState } from "./state.js";

export class NoAccessError extends Error {
  constructor(url) {
    super("The extension doesn't have access to this site yet.");
    this.name = "NoAccessError";
    this.code = "no_access";
    this.url = url;
  }
}

const RESTRICTED = /^(chrome|chrome-extension|edge|about|devtools|view-source|chrome-search|chrome-untrusted):|^https:\/\/(chrome\.google\.com\/webstore|chromewebstore\.google\.com)/i;

async function inject(tabId, func, args = [], world = "ISOLATED") {
  const [r] = await chrome.scripting.executeScript({ target: { tabId }, func, args, world });
  return r?.result;
}

/** Fetch from the extension (needs host permission) as a fallback for cross-origin resources. */
async function extFetch(url, { binary = false, maxBytes = 2e6 } = {}) {
  try {
    const origin = new URL(url).origin;
    if (!(await chrome.permissions.contains({ origins: [`${origin}/*`] }))) return { url, ok: false, status: 0, error: "no permission" };
    const res = await fetch(url, { credentials: "omit", cache: "no-store" });
    const buf = new Uint8Array(await res.arrayBuffer()).subarray(0, maxBytes);
    const headers = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    return { url, ok: res.ok, status: res.status, headers, size: buf.length, text: binary ? undefined : new TextDecoder().decode(buf), bytes: binary ? buf : undefined };
  } catch (e) {
    return { url, ok: false, status: 0, error: e.message };
  }
}

/** Fetch same-origin URLs through the page, others through the extension. */
export async function fetchMany(tabId, origin, reqs) {
  const same = reqs.filter((r) => r.url.startsWith(`${origin}/`));
  const other = reqs.filter((r) => !r.url.startsWith(`${origin}/`));
  const results = new Map();
  if (same.length) {
    const out = (await inject(tabId, pageFetch, [same]).catch(() => [])) || [];
    for (const r of out) {
      if (r?.b64) r.bytes = base64ToBytes(r.b64);
      if (r) results.set(r.url, r);
    }
  }
  for (const r of other) results.set(r.url, await extFetch(r.url, r));
  // A cross-origin resource may still be readable from the page when it sends CORS headers.
  const retry = other.filter((r) => !results.get(r.url)?.ok);
  if (retry.length) {
    const out = (await inject(tabId, pageFetch, [retry]).catch(() => [])) || [];
    for (const r of out) {
      if (!r?.ok) continue;
      if (r.b64) r.bytes = base64ToBytes(r.b64);
      results.set(r.url, r);
    }
  }
  return results;
}

/**
 * Scan a tab. Returns the stored report.
 * @param {number} tabId
 */
export async function scanTab(tabId) {
  const settings = await getSettings();
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url || RESTRICTED.test(tab.url)) throw new Error("Chrome doesn't let extensions read this page (browser pages, the Web Store and the built-in PDF viewer are off-limits). Open a regular website.");
  if (/^file:/i.test(tab.url) && !(await chrome.extension.isAllowedFileSchemeAccess())) throw new Error('To scan local files, enable "Allow access to file URLs" for this extension on chrome://extensions.');

  await setTabState(tabId, { status: "running", step: "Reading the page", error: null, errorCode: null });
  const t0 = Date.now();
  let page;
  try {
    page = await inject(tabId, collectPage, [{ includeFormValues: settings.scan.includeFormValues }]);
  } catch (e) {
    if (/Cannot access|permission|host/i.test(e.message)) throw new NoAccessError(tab.url);
    throw new Error(`Couldn't read the page: ${e.message}`);
  }
  if (!page) throw new Error("The page returned no data (it may still be loading). Try again.");

  let probe = {};
  if (settings.scan.mainWorldProbe) probe = (await inject(tabId, probeMainWorld, [], "MAIN").catch(() => null)) || {};

  const origin = page.origin;
  const isHttp = /^https?:/.test(origin);
  const extra = {};
  if (isHttp) {
    await setTabState(tabId, { step: "Reading the site's public files" });
    const reqs = [{ url: page.url.replace(/#.*$/, ""), maxBytes: 65536 }];
    if (settings.scan.wellKnown) {
      for (const p of ["/robots.txt", "/.well-known/security.txt", "/security.txt", "/humans.txt", "/ads.txt", "/app-ads.txt", "/sitemap.xml"]) reqs.push({ url: `${origin}${p}`, maxBytes: 600000 });
      const manifest = page.linkTags.find((l) => l.rel === "manifest")?.href;
      if (manifest) reqs.push({ url: manifest, maxBytes: 200000 });
    }
    const scriptUrls = settings.scan.externalScripts ? [...new Set(page.scripts.filter((s) => s.src && /^https?:/.test(s.src)).map((s) => s.src))].slice(0, settings.scan.maxScripts) : [];
    for (const u of scriptUrls) reqs.push({ url: u, maxBytes: 1_500_000 });
    const favUrl = settings.scan.favicon ? page.favicons[0] : null;
    if (favUrl && /^https?:/.test(favUrl)) reqs.push({ url: favUrl, binary: true, maxBytes: 1_000_000 });

    const res = await fetchMany(tabId, origin, reqs);
    // Missing files often come back as an HTML "not found" page with status 200; ignore those.
    const ok = (u) => {
      const r = res.get(u);
      return r?.ok && r.status < 400 && !/text\/html/i.test(r.headers?.["content-type"] || "") ? r : null;
    };
    extra.docResponse = res.get(page.url.replace(/#.*$/, "")) || null;
    if (extra.docResponse && !extra.docResponse.ok && !extra.docResponse.status) extra.docResponse = null;
    if (settings.scan.wellKnown) {
      extra.robots = ok(`${origin}/robots.txt`);
      extra.security = ok(`${origin}/.well-known/security.txt`) || ok(`${origin}/security.txt`);
      extra.humans = ok(`${origin}/humans.txt`);
      extra.ads = ok(`${origin}/ads.txt`);
      extra.appAds = ok(`${origin}/app-ads.txt`);
      extra.sitemap = ok(`${origin}/sitemap.xml`);
      const manifest = page.linkTags.find((l) => l.rel === "manifest")?.href;
      if (manifest) extra.manifest = res.get(manifest)?.ok ? res.get(manifest) : null;
      // robots.txt may name a different sitemap.
      if (!extra.sitemap && extra.robots) {
        const sm = parseRobots(extra.robots.text).sitemaps[0];
        if (sm) extra.sitemap = (await fetchMany(tabId, origin, [{ url: sm, maxBytes: 600000 }])).get(sm) || null;
      }
    }
    extra.scripts = scriptUrls.map((u) => res.get(u)).filter((r) => r?.ok && r.text).map((r) => ({ url: r.url, text: r.text }));
    extra.scriptsSkipped = scriptUrls.length - extra.scripts.length;
    if (favUrl) {
      const f = res.get(favUrl);
      if (f?.ok && f.bytes?.length && !/text\/html/i.test(f.headers?.["content-type"] || "")) extra.favicon = { url: favUrl, bytes: f.bytes, type: f.headers?.["content-type"] || "" };
      else if (favUrl !== page.favicons[page.favicons.length - 1]) {
        // Fall back to /favicon.ico.
        const fb = page.favicons[page.favicons.length - 1];
        const r = (await fetchMany(tabId, origin, [{ url: fb, binary: true, maxBytes: 1_000_000 }])).get(fb);
        if (r?.ok && r.bytes?.length && !/text\/html/i.test(r.headers?.["content-type"] || "")) extra.favicon = { url: fb, bytes: r.bytes, type: r.headers?.["content-type"] || "" };
      }
    }
  }

  await setTabState(tabId, { step: "Analysing" });
  const report = buildReport(page, probe, extra);
  report.id = newId();
  report.createdAt = new Date().toISOString();
  report.tabId = tabId;
  report.scanMs = Date.now() - t0;
  report.notes = "";
  report.tags = [];
  report.scriptsFetched = extra.scripts?.length || 0;
  report.scriptsSkipped = extra.scriptsSkipped || 0;
  report.runtime = { globals: probe.globals || {}, ids: probe.runtimeIds || [], configKeys: Object.keys(probe.configs || {}) };

  if (extra.favicon) {
    const h = await faviconHashes(extra.favicon.bytes);
    report.favicon = { url: extra.favicon.url, type: extra.favicon.type, ...h };
    report.indicators.push({ type: "favicon", value: String(h.mmh3), label: "MurmurHash3 (Shodan)", count: 1, sources: ["favicon"], contexts: [], extra: { mmh3: h.mmh3, md5: h.md5, sha256: h.sha256 }, confidence: "high" });
    report.counts.favicon = 1;
  }

  report.correlations = await correlate(report).catch(() => []);
  await putReport(report);
  if (settings.privacy.keepHistory) pruneReports(settings.privacy.historyLimit).catch(() => {});
  await setTabState(tabId, { status: "done", step: null, reportId: report.id, url: page.url });
  return report;
}
