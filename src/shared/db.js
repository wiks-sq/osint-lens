// IndexedDB storage for reports, the cross-scan indicator index and evidence.
//
// Extension pages and the service worker share one origin, so the side panel
// reads reports directly from here while the service worker writes them.
// Everything stays on this computer.

const DB_NAME = "osint-lens";
const DB_VERSION = 1;
let dbPromise = null;

export function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("reports")) {
        const s = db.createObjectStore("reports", { keyPath: "id" });
        s.createIndex("createdAt", "createdAt");
        s.createIndex("site", "page.site");
      }
      if (!db.objectStoreNames.contains("indicators")) {
        // One row per (indicator, report): key "type|value|reportId".
        const s = db.createObjectStore("indicators", { keyPath: "key" });
        s.createIndex("ind", "ind");
        s.createIndex("reportId", "reportId");
      }
      if (!db.objectStoreNames.contains("evidence")) {
        const s = db.createObjectStore("evidence", { keyPath: "id" });
        s.createIndex("reportId", "reportId");
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error("Database is blocked by another open version"));
  });
  dbPromise.catch(() => (dbPromise = null));
  return dbPromise;
}

const promisify = (req) => new Promise((res, rej) => {
  req.onsuccess = () => res(req.result);
  req.onerror = () => rej(req.error);
});

async function tx(stores, mode, fn) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, mode);
    let out;
    Promise.resolve(fn(t)).then((v) => (out = v), reject);
    t.oncomplete = () => resolve(out);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error("Transaction aborted"));
  });
}

/** Normalised identity used by the index (mirrors core/indicators.js indicatorKey). */
export const indKey = (type, value) => `${type}|${String(value).trim().toLowerCase()}`;

/** Types worth correlating across investigations (generic URLs/hosts are too noisy). */
const INDEXED_TYPES = new Set(["domain", "ip", "email", "phone", "social", "crypto", "onion", "tracker", "verification", "favicon", "asn", "api_key_public", "bucket", "business_id", "iban", "organization", "person", "handle"]);

export async function putReport(report) {
  return tx(["reports", "indicators"], "readwrite", async (t) => {
    t.objectStore("reports").put(report);
    const idx = t.objectStore("indicators");
    const old = await promisify(idx.index("reportId").getAllKeys(report.id));
    for (const k of old) idx.delete(k);
    for (const i of report.indicators || []) {
      if (!INDEXED_TYPES.has(i.type)) continue;
      // Third-party service domains (CDNs, analytics) would link every site to every other one.
      if (i.type === "domain" && !i.extra?.primary && i.sources.every((s) => s.startsWith("third-party"))) continue;
      const ind = indKey(i.type, i.value);
      idx.put({ key: `${ind}|${report.id}`, ind, reportId: report.id, type: i.type, value: i.value, label: i.label || null, site: report.page.site, url: report.page.url, createdAt: report.createdAt });
    }
  });
}

export async function getReport(id) {
  return tx(["reports"], "readonly", (t) => promisify(t.objectStore("reports").get(id)));
}

/** Lightweight list for the history view (newest first). */
export async function listReports(limit = 200) {
  return tx(["reports"], "readonly", (t) => new Promise((resolve, reject) => {
    const out = [];
    const req = t.objectStore("reports").index("createdAt").openCursor(null, "prev");
    req.onsuccess = () => {
      const c = req.result;
      if (!c || out.length >= limit) return resolve(out);
      const r = c.value;
      out.push({ id: r.id, url: r.page.url, title: r.page.title, site: r.page.site, createdAt: r.createdAt, tags: r.tags || [], notes: !!r.notes, risk: r.phishing?.level, exposures: (r.exposures || []).length, indicators: (r.indicators || []).length, ai: !!r.ai?.result, starred: !!r.starred });
      c.continue();
    };
    req.onerror = () => reject(req.error);
  }));
}

export async function deleteReport(id) {
  return tx(["reports", "indicators", "evidence"], "readwrite", async (t) => {
    t.objectStore("reports").delete(id);
    for (const store of ["indicators", "evidence"]) {
      const s = t.objectStore(store);
      for (const k of await promisify(s.index("reportId").getAllKeys(id))) s.delete(k);
    }
  });
}

/** Keep at most `limit` reports (starred ones are never pruned). */
export async function pruneReports(limit) {
  const all = await listReports(100000);
  const victims = all.filter((r) => !r.starred).slice(limit);
  for (const r of victims) await deleteReport(r.id);
  return victims.length;
}

export async function clearAll() {
  return tx(["reports", "indicators", "evidence"], "readwrite", (t) => {
    for (const s of ["reports", "indicators", "evidence"]) t.objectStore(s).clear();
  });
}

/**
 * Other reports that share indicators with this one.
 * @returns {Promise<Array<{type, value, label, others: Array<{reportId, site, url, createdAt}>}>>}
 */
export async function correlate(report) {
  const out = [];
  await tx(["indicators"], "readonly", async (t) => {
    const idx = t.objectStore("indicators").index("ind");
    for (const i of report.indicators || []) {
      if (!INDEXED_TYPES.has(i.type)) continue;
      const rows = await promisify(idx.getAll(indKey(i.type, i.value), 50));
      const others = rows.filter((r) => r.reportId !== report.id && r.site !== report.page.site);
      if (!others.length) continue;
      const bySite = new Map();
      for (const r of others) if (!bySite.has(r.site) || bySite.get(r.site).createdAt < r.createdAt) bySite.set(r.site, r);
      out.push({ type: i.type, value: i.value, label: i.label, others: [...bySite.values()].map((r) => ({ reportId: r.reportId, site: r.site, url: r.url, createdAt: r.createdAt })) });
    }
  });
  // Strong, account-level identifiers first.
  const rank = { tracker: 0, verification: 0, api_key_public: 1, favicon: 1, crypto: 1, email: 2, phone: 2, social: 2, bucket: 2 };
  return out.sort((a, b) => (rank[a.type] ?? 5) - (rank[b.type] ?? 5) || b.others.length - a.others.length);
}

/** Search the index for any value (used by the history search box). */
export async function searchIndicators(q, limit = 200) {
  q = String(q).trim().toLowerCase();
  if (!q) return [];
  return tx(["indicators"], "readonly", (t) => new Promise((resolve, reject) => {
    const out = [];
    const req = t.objectStore("indicators").openCursor();
    req.onsuccess = () => {
      const c = req.result;
      if (!c || out.length >= limit) return resolve(out);
      if (c.value.ind.includes(q)) out.push(c.value);
      c.continue();
    };
    req.onerror = () => reject(req.error);
  }));
}

export async function putEvidence(item) {
  return tx(["evidence"], "readwrite", (t) => t.objectStore("evidence").put(item));
}

export async function getEvidence(id) {
  return tx(["evidence"], "readonly", (t) => promisify(t.objectStore("evidence").get(id)));
}

export async function listEvidence(reportId) {
  return tx(["evidence"], "readonly", (t) => promisify(t.objectStore("evidence").index("reportId").getAll(reportId)));
}
