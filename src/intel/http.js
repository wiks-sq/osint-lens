// fetch() with a timeout, a response size cap and readable errors. Used by
// every online lookup so a slow or huge response can't stall a scan.

export class HttpError extends Error {
  constructor(message, status = 0, body = "") {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.body = body;
  }
}

/**
 * @param {string} url
 * @param {object} [o]
 * @param {number} [o.timeoutMs=20000]
 * @param {number} [o.maxBytes=8e6]
 * @param {"json"|"text"|"bytes"} [o.as="json"]
 * @param {object} [o.headers]
 * @param {string} [o.method]
 * @param {any}    [o.body]
 * @param {AbortSignal} [o.signal]
 * @param {number} [o.retries=0]  retries on network errors and 429/5xx
 */
export async function httpGet(url, o = {}) {
  const attempts = (o.retries ?? 0) + 1;
  let lastErr;
  for (let a = 0; a < attempts; a++) {
    try {
      return await once(url, o);
    } catch (e) {
      lastErr = e;
      const retryable = !(e instanceof HttpError) || e.status === 429 || e.status >= 500 || e.status === 0;
      if (!retryable || a === attempts - 1 || o.signal?.aborted) throw e;
      await new Promise((r) => setTimeout(r, 800 * (a + 1) ** 2));
    }
  }
  throw lastErr;
}

async function once(url, o) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error("timeout")), o.timeoutMs ?? 20000);
  const onAbort = () => ctrl.abort(o.signal.reason);
  o.signal?.addEventListener("abort", onAbort, { once: true });
  let res;
  try {
    res = await fetch(url, {
      method: o.method || "GET",
      headers: o.headers,
      body: o.body,
      signal: ctrl.signal,
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
      referrerPolicy: "no-referrer"
    });
  } catch (e) {
    clearTimeout(timer);
    o.signal?.removeEventListener("abort", onAbort);
    const host = safeHost(url);
    if (ctrl.signal.aborted && !o.signal?.aborted) throw new HttpError(`${host} didn't answer within ${Math.round((o.timeoutMs ?? 20000) / 1000)}s`, 0);
    if (o.signal?.aborted) throw new HttpError("Cancelled", 0);
    throw new HttpError(`Couldn't reach ${host} (${e.message || "network error"})`, 0);
  }
  try {
    const max = o.maxBytes ?? 8e6;
    const bytes = await readCapped(res, max);
    if (!res.ok) {
      const body = new TextDecoder().decode(bytes.subarray(0, 2000));
      throw new HttpError(`${safeHost(url)} returned HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ""}`, res.status, body);
    }
    if (o.as === "bytes") return { bytes, headers: res.headers, status: res.status, url: res.url };
    const text = new TextDecoder().decode(bytes);
    if (o.as === "text") return text;
    try {
      return JSON.parse(text);
    } catch {
      throw new HttpError(`${safeHost(url)} returned invalid JSON`, res.status, text.slice(0, 500));
    }
  } finally {
    clearTimeout(timer);
    o.signal?.removeEventListener("abort", onAbort);
  }
}

async function readCapped(res, max) {
  if (!res.body) return new Uint8Array(await res.arrayBuffer()).subarray(0, max);
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
  const out = new Uint8Array(Math.min(total, max));
  let p = 0;
  for (const c of chunks) {
    const n = Math.min(c.length, out.length - p);
    out.set(c.subarray(0, n), p);
    p += n;
    if (p >= out.length) break;
  }
  return out;
}

export function safeHost(url) {
  try {
    return new URL(url).host;
  } catch {
    return String(url).slice(0, 60);
  }
}
