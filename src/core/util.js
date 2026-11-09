// Small helpers shared by the core modules.
//
// Everything in src/core is pure: no chrome.* APIs, no DOM, no network. That
// keeps the analysis logic unit-testable in Node (see tests/).

/** Clamp a number into [lo, hi]. */
export const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));

/** Collapse whitespace and trim. */
export const squash = (s) => String(s ?? "").replace(/\s+/g, " ").trim();

/** Truncate to `n` characters, adding an ellipsis when cut. */
export const trunc = (s, n) => {
  s = String(s ?? "");
  return s.length > n ? `${s.slice(0, Math.max(0, n - 1))}…` : s;
};

/** Text around a match, single-line, `pad` characters on either side. */
export function contextOf(text, index, length, pad = 40) {
  const start = Math.max(0, index - pad);
  const end = Math.min(text.length, index + length + pad);
  return (start > 0 ? "…" : "") + squash(text.slice(start, end)) + (end < text.length ? "…" : "");
}

/** Escape a string for use inside a RegExp. */
export const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Parse a URL without throwing. */
export function safeUrl(href, base) {
  try {
    return new URL(href, base);
  } catch {
    return null;
  }
}

/** Unique values, keeping first-seen order. `key` maps an item to its identity. */
export function uniqBy(items, key = (x) => x) {
  const seen = new Set();
  const out = [];
  for (const it of items) {
    const k = key(it);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(it);
  }
  return out;
}

/** Group items into a Map by key. */
export function groupBy(items, key) {
  const m = new Map();
  for (const it of items) {
    const k = key(it);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(it);
  }
  return m;
}

/** Count occurrences into a plain object. */
export function countBy(items, key) {
  const o = {};
  for (const it of items) {
    const k = key(it);
    o[k] = (o[k] || 0) + 1;
  }
  return o;
}

/** Shannon entropy in bits per character. Used to tell real secrets from placeholders. */
export function entropy(s) {
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Mask a sensitive value for display: keep the start and end, hide the middle.
 * "4111111111111111" -> "4111••••••••1111". Values of 4 characters or fewer are fully hidden.
 */
export function mask(value) {
  const v = String(value ?? "");
  if (v.length <= 4) return "•".repeat(v.length);
  const keep = v.length <= 8 ? 1 : v.length <= 12 ? 2 : 4;
  return v.slice(0, keep) + "•".repeat(Math.min(12, v.length - keep * 2)) + v.slice(-keep);
}

/** Bytes -> lowercase hex. */
export const toHex = (bytes) =>
  Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

/** Bytes -> base64 (works in browsers, service workers and Node). */
export function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < u8.length; i += 0x8000) bin += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** base64 -> bytes. Accepts base64url too. */
export function base64ToBytes(b64) {
  const s = String(b64).replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const bin = atob(s + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** SHA-256 / SHA-1 hex digest via WebCrypto. */
export async function digestHex(algo, data) {
  const buf = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return toHex(new Uint8Array(await crypto.subtle.digest(algo, buf)));
}

/** Human-readable byte size. */
export function formatBytes(n) {
  if (!Number.isFinite(n)) return "?";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i && n < 10 ? 1 : 0)} ${units[i]}`;
}

/** Whole days between two dates (b defaults to now). */
export const daysBetween = (a, b = Date.now()) => Math.floor((new Date(b) - new Date(a)) / 86400000);

/** Run `fn` over items with at most `limit` in flight. Results keep input order. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** Severity ordering helper. */
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const bySeverity = (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
