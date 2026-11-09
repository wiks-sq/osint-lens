// HTTP response header analysis: security posture, infrastructure leaks and
// the third-party hosts a Content-Security-Policy reveals (a CSP lists every
// service the site is allowed to talk to, including ones not used on this page).

/** Parse a CSP into { directive: [sources] }. */
export function parseCsp(csp) {
  const out = {};
  for (const part of String(csp || "").split(";")) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name) out[name.toLowerCase()] = vals;
  }
  return out;
}

/** Hosts named in a CSP (wildcards kept, e.g. "*.example.com"). */
export function cspHosts(csp) {
  const hosts = new Set();
  for (const vals of Object.values(parseCsp(csp))) {
    for (const v of vals) {
      if (/^'|^(?:data|blob|mediastream|filesystem|https?|wss?):?$/i.test(v)) continue;
      const m = /^(?:[a-z][a-z0-9+.\-]*:\/\/)?(\*\.)?([a-z0-9.\-]+\.[a-z]{2,})(?::\d+|:\*)?(?:\/.*)?$/i.exec(v);
      if (m) hosts.add(((m[1] || "") + m[2]).toLowerCase());
    }
  }
  return [...hosts].sort();
}

const CHECKS = [
  {
    id: "hsts",
    header: "strict-transport-security",
    title: "Strict-Transport-Security (HSTS)",
    evaluate(v, ctx) {
      if (!ctx.https) return { status: "info", note: "Page is not served over HTTPS." };
      if (!v) return { status: "fail", note: "Missing: browsers may be downgraded to HTTP on first visit." };
      const age = Number((/max-age=(\d+)/i.exec(v) || [])[1] || 0);
      if (age < 15552000) return { status: "warn", note: `max-age is ${age}s; 6 months (15552000) or more is recommended.` };
      return { status: "pass", note: /preload/i.test(v) ? "Long max-age, preload requested." : "Long max-age." };
    }
  },
  {
    id: "csp",
    header: "content-security-policy",
    title: "Content-Security-Policy",
    evaluate(v, ctx) {
      if (!v) {
        if (ctx.headers["content-security-policy-report-only"]) return { status: "warn", note: "Only a report-only policy is set; nothing is enforced." };
        return { status: "fail", note: "Missing: no defence-in-depth against XSS and data injection." };
      }
      const p = parseCsp(v);
      const script = p["script-src"] || p["default-src"] || [];
      const issues = [];
      if (script.includes("'unsafe-inline'") && !script.some((s) => /^'(?:nonce|sha\d{3})-/.test(s) || s === "'strict-dynamic'")) issues.push("'unsafe-inline' scripts");
      if (script.includes("'unsafe-eval'")) issues.push("'unsafe-eval'");
      if (script.some((s) => s === "*" || s === "https:" || s === "http:")) issues.push("wildcard script sources");
      if (!p["object-src"] && !(p["default-src"] || []).includes("'none'")) issues.push("no object-src");
      if (!p["frame-ancestors"]) issues.push("no frame-ancestors");
      return issues.length ? { status: "warn", note: `Weak points: ${issues.join(", ")}.` } : { status: "pass", note: "Policy present with no obvious weak points." };
    }
  },
  {
    id: "xfo",
    header: "x-frame-options",
    title: "Clickjacking protection",
    evaluate(v, ctx) {
      const fa = parseCsp(ctx.headers["content-security-policy"])["frame-ancestors"];
      if (fa) return { status: "pass", note: `CSP frame-ancestors ${fa.join(" ")}` };
      if (!v) return { status: "warn", note: "No X-Frame-Options or CSP frame-ancestors: the page can be framed by other sites." };
      return { status: /deny|sameorigin/i.test(v) ? "pass" : "warn", note: `X-Frame-Options: ${v}` };
    }
  },
  {
    id: "xcto",
    header: "x-content-type-options",
    title: "X-Content-Type-Options",
    evaluate: (v) => (/nosniff/i.test(v || "") ? { status: "pass", note: "nosniff" } : { status: "warn", note: "Missing nosniff: browsers may MIME-sniff responses." })
  },
  {
    id: "referrer",
    header: "referrer-policy",
    title: "Referrer-Policy",
    evaluate: (v) =>
      !v ? { status: "info", note: "Not set (browser default strict-origin-when-cross-origin applies)." }
        : /unsafe-url|no-referrer-when-downgrade/i.test(v) ? { status: "warn", note: `${v}: full URLs leak to other sites.` }
          : { status: "pass", note: v }
  },
  {
    id: "permissions",
    header: "permissions-policy",
    title: "Permissions-Policy",
    evaluate: (v) => (v ? { status: "pass", note: "Set." } : { status: "info", note: "Not set." })
  },
  {
    id: "coop",
    header: "cross-origin-opener-policy",
    title: "Cross-Origin-Opener-Policy",
    evaluate: (v) => (v ? { status: "pass", note: v } : { status: "info", note: "Not set." })
  },
  {
    id: "cors",
    header: "access-control-allow-origin",
    title: "CORS",
    evaluate(v, ctx) {
      if (!v) return { status: "pass", note: "No CORS header on the page itself." };
      if (v === "*" && /true/i.test(ctx.headers["access-control-allow-credentials"] || "")) return { status: "fail", note: "Wildcard origin with credentials." };
      return { status: v === "*" ? "info" : "pass", note: `Access-Control-Allow-Origin: ${v}` };
    }
  }
];

/** Headers that disclose software, versions or internal infrastructure. */
const LEAK_HEADERS = [
  "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime",
  "x-backend-server", "x-backend", "x-server", "x-served-by", "x-host", "x-upstream", "x-forwarded-server", "x-real-server",
  "via", "x-cache", "x-varnish", "x-amz-cf-pop", "cf-ray", "x-request-id", "x-github-request-id", "x-vercel-id", "x-nf-request-id",
  "x-debug-token", "x-debug-token-link", "x-litespeed-cache", "x-turbo-charged-by", "x-shopid", "x-wix-request-id", "x-hs-hub-id",
  "x-pingback", "link", "x-cluster-name", "x-node", "x-datacenter", "x-envoy-upstream-service-time", "x-kong-upstream-latency",
  "x-oracle-dms-ecid", "x-sap-system", "x-original-url", "x-rewrite-url", "x-redirect-by"
];

/**
 * Analyse response headers (lowercase keys).
 * @param {Object<string,string>} headers
 * @param {string} url
 */
export function analyzeHeaders(headers, url) {
  headers = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), String(v)]));
  const https = /^https:/i.test(url);
  const ctx = { headers, https };
  const checks = CHECKS.map((c) => ({ id: c.id, title: c.title, value: headers[c.header] || null, ...c.evaluate(headers[c.header], ctx) }));

  const leaks = [];
  for (const h of LEAK_HEADERS) {
    if (!headers[h]) continue;
    const v = headers[h];
    const versioned = /\d+\.\d+/.test(v);
    leaks.push({ header: h, value: v, versioned, note: versioned ? "discloses a software version" : null });
  }
  // Internal hostnames and private IPs leaking through any header.
  for (const [h, v] of Object.entries(headers)) {
    if (/(?:^|[^\d])(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/.test(v)) {
      leaks.push({ header: h, value: v, versioned: false, note: "contains a private IP address" });
    } else if (/\b[a-z0-9\-]+\.(?:internal|local|corp|lan|intranet|localdomain)\b/i.test(v)) {
      leaks.push({ header: h, value: v, versioned: false, note: "contains an internal hostname" });
    }
  }

  const score = checks.reduce((s, c) => s + (c.status === "pass" ? 1 : c.status === "warn" ? 0.5 : c.status === "fail" ? 0 : 0.75), 0) / checks.length;
  const grade = score >= 0.9 ? "A" : score >= 0.78 ? "B" : score >= 0.65 ? "C" : score >= 0.5 ? "D" : "F";
  return {
    https,
    grade,
    checks,
    leaks,
    cspHosts: cspHosts(headers["content-security-policy"] || headers["content-security-policy-report-only"]),
    reportTo: headers["report-to"] || headers["reporting-endpoints"] || null
  };
}

/** Cookie names visible to JavaScript, with what they suggest. */
export function analyzeCookies(names) {
  const SESSION = /^(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid|session|sid|connect\.sid|laravel_session|_session_id|.*_session)$/i;
  return (names || []).map((n) => ({
    name: n,
    note: SESSION.test(n) ? "Session cookie readable by JavaScript (no HttpOnly): exposed to XSS" : null
  }));
}
