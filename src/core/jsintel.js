// What the site's own JavaScript reveals: API endpoints, cloud storage
// buckets, internal and pre-production hostnames, source maps, build-time
// environment variables and developer comments.

import { safeUrl } from "./util.js";

const BUCKET_RULES = [
  ["Amazon S3", /\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com\b/gi],
  ["Amazon S3", /\/\/s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com\/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?=[/"'?\s])/gi],
  ["Google Cloud Storage", /\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])(?=[/"'?\s])/gi],
  ["Google Cloud Storage", /\b([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b/gi],
  ["Firebase Storage", /\b([a-z0-9\-]+\.(?:appspot\.com|firebasestorage\.app))\b/gi],
  ["Azure Blob Storage", /\b([a-z0-9]{3,24})\.blob\.core\.windows\.net\b/gi],
  ["DigitalOcean Spaces", /\b([a-z0-9\-]{3,63})\.[a-z0-9]+\.digitaloceanspaces\.com\b/gi],
  ["Cloudflare R2", /\b(pub-[a-f0-9]{32})\.r2\.dev\b|\b([a-f0-9]{32})\.r2\.cloudflarestorage\.com\b/gi],
  ["Backblaze B2", /\bf\d{3}\.backblazeb2\.com\/file\/([a-z0-9\-]{3,63})/gi],
  ["Wasabi", /\b([a-z0-9.\-]{3,63})\.s3\.[a-z0-9\-]*\.?wasabisys\.com\b/gi],
  ["Alibaba OSS", /\b([a-z0-9\-]{3,63})\.oss-[a-z0-9\-]+\.aliyuncs\.com\b/gi]
];

// Hostnames only count inside strings or URLs (code like "re.test(" or "a.local" isn't a host).
const INTERNAL_HOST_RE = /(?<=["'`@]|\/\/)((?:[a-z0-9\-]+\.)+(?:internal|intranet|local|localdomain|corp|lan|home\.arpa|private))(?::\d{2,5})?(?=[\/"'`:?#\s]|$)|(?<=["'`]|\/\/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d{2,5}\b/gi;
const PREPROD_HOST_RE = /(?<=["'`@]|\/\/)((?:[a-z0-9\-]+\.)*(?:dev|develop|development|stage|staging|stg|uat|qa|test|testing|sandbox|preprod|pre-prod|preview|beta|demo|int|integration|internal|admin|vpn|jenkins|gitlab|jira|confluence|grafana|kibana|sonar|nexus|artifactory)[0-9\-]*\.(?:[a-z0-9\-]+\.)+[a-z]{2,24})\b/gi;
const ENDPOINT_RE = /["'`]((?:https?:)?\/\/[a-z0-9.\-]+(?::\d+)?\/[^"'`\s<>{}]{0,200}|\/(?:api|v\d|graphql|gql|rest|rpc|internal|admin|auth|oauth|users?|accounts?|graph|services?|ajax|wp-json|json|data)\b[^"'`\s<>{}]{0,200})["'`]/gi;
const SOURCEMAP_RE = /[#@]\s*sourceMappingURL=([^\s'"*]+)/g;
const WS_RE = /["'`](wss?:\/\/[a-z0-9.\-]+(?::\d+)?[^"'`\s]{0,200})["'`]/gi;
const ENV_RE = /\b((?:NEXT_PUBLIC|REACT_APP|VUE_APP|VITE|NUXT_PUBLIC|GATSBY|EXPO_PUBLIC|PUBLIC|NG_APP)_[A-Z0-9_]{2,60})["']?\s*[:=]\s*["'`]([^"'`]{1,300})["'`]/g;
const DEV_COMMENT_RE = /(?:\/\/|\/\*|<!--)\s*((?:TODO|FIXME|HACK|XXX|BUG|DEBUG|NOTE|TEMP|password|passwd|secret|api[_\s-]?key|token|internal|remove before|do not commit|staging|credentials?)\b[^\n]{0,200})/gi;

/**
 * Analyse script source text.
 * @param {Array<{url:string|null, text:string}>} scripts  inline scripts have url null
 * @param {string} pageUrl
 */
export function analyzeScripts(scripts, pageUrl) {
  const endpoints = new Map();
  const buckets = new Map();
  const internal = new Set();
  const preprod = new Set();
  const sourcemaps = new Set();
  const websockets = new Set();
  const env = new Map();
  const comments = [];
  const page = safeUrl(pageUrl);

  for (const s of scripts || []) {
    const text = s.text || "";
    if (!text) continue;
    const where = s.url || "inline script";

    for (const m of text.matchAll(ENDPOINT_RE)) {
      const raw = m[1];
      if (/\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|css|map)(?:[?#]|$)/i.test(raw)) continue;
      if (/^\/\/(?:www\.)?(?:w3\.org|schema\.org|google-analytics\.com|googletagmanager\.com)/.test(raw)) continue;
      const abs = safeUrl(raw, pageUrl);
      const key = abs ? abs.href.replace(/[?#].*$/, "") : raw;
      if (!endpoints.has(key)) endpoints.set(key, { url: key, raw, source: where, sameSite: abs ? abs.hostname === page?.hostname : true });
      if (endpoints.size > 400) break;
    }
    for (const [provider, re] of BUCKET_RULES) {
      for (const m of text.matchAll(re)) {
        const name = (m[1] || m[2] || "").toLowerCase();
        if (!name || /^(www|s3|cdn|static|assets)$/.test(name)) continue;
        const k = `${provider}|${name}`;
        if (!buckets.has(k)) buckets.set(k, { provider, name, evidence: m[0].slice(0, 200), source: where });
      }
    }
    for (const m of text.matchAll(INTERNAL_HOST_RE)) {
      const h = m[0].toLowerCase();
      if (!/^(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(?:80|443)$/.test(h)) internal.add(h);
    }
    for (const m of text.matchAll(PREPROD_HOST_RE)) {
      const h = m[1].toLowerCase();
      if (!/\.(?:js|css|json|png|svg)$/.test(h) && !/(?:^|\.)(?:w3|schema|mozilla|github|googleapis|gstatic|cloudflare|jsdelivr|unpkg)\./.test(h)) preprod.add(h);
    }
    for (const m of text.matchAll(SOURCEMAP_RE)) {
      if (/^data:/.test(m[1])) {
        sourcemaps.add(`${where} (inline data: map)`);
        continue;
      }
      const abs = safeUrl(m[1], s.url || pageUrl);
      if (abs) sourcemaps.add(abs.href);
    }
    for (const m of text.matchAll(WS_RE)) websockets.add(m[1]);
    for (const m of text.matchAll(ENV_RE)) if (!env.has(m[1])) env.set(m[1], { name: m[1], value: m[2], source: where });
    if (comments.length < 60) {
      for (const m of text.matchAll(DEV_COMMENT_RE)) {
        comments.push({ text: m[1].trim().slice(0, 200), source: where });
        if (comments.length >= 60) break;
      }
    }
  }

  return {
    endpoints: [...endpoints.values()].sort((a, b) => Number(b.sameSite) - Number(a.sameSite) || a.url.localeCompare(b.url)),
    buckets: [...buckets.values()],
    internalHosts: [...internal].slice(0, 100),
    preprodHosts: [...preprod].slice(0, 100),
    sourcemaps: [...sourcemaps].slice(0, 100),
    websockets: [...websockets].slice(0, 50),
    env: [...env.values()].slice(0, 100),
    comments
  };
}

/** Interesting HTML comments (developer notes, credentials, internal references). */
export function analyzeComments(comments) {
  const out = [];
  for (const c of comments || []) {
    const t = String(c).trim();
    if (t.length < 4 || /^\[(?:if |endif)|^\/?ko\b|^#/i.test(t)) continue;
    const flagged = /todo|fixme|hack|debug|password|passwd|secret|token|api.?key|internal|staging|\bdev\b|\btest|admin|remove|temporary|credential|deprecated|backup|\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+|[a-z0-9._-]+@[a-z0-9-]+\.[a-z]{2,}/i.test(t);
    // Short structural markers ("header", "end nav") are noise unless they say something interesting.
    if (!flagged && /^\s*(?:end|\/)?\s*[\w\- ]{0,30}\s*$/i.test(t)) continue;
    out.push({ text: t.length > 400 ? `${t.slice(0, 400)}…` : t, flagged });
  }
  return out.sort((a, b) => Number(b.flagged) - Number(a.flagged)).slice(0, 200);
}
