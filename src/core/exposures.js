// Exposure detectors: credentials, secrets and personal data that should not
// be public. This is the "is this page leaking something?" half of the tool.
//
// Each detector: { id, label, severity, re (global), group?, validate?, minEntropy? }
// Detectors run in order; a later detector skips text an earlier one claimed,
// so specific patterns go first.

import { contextOf, entropy, mask } from "./util.js";
import { luhn, cardBrand, iban, finnishHetu, usSsn } from "./validators.js";

export const DETECTORS = [
  // --- Private keys and cloud credentials --------------------------------------
  { id: "private_key", label: "Private key", severity: "critical", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
  { id: "private_key_header", label: "Private key (header only)", severity: "high", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g },
  { id: "aws_access_key", label: "AWS access key ID", severity: "high", re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { id: "aws_secret", label: "AWS secret access key", severity: "critical", re: /aws.{0,20}?(?:secret|private).{0,20}?['"=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi, group: 1, minEntropy: 4 },
  { id: "gcp_service_account", label: "Google Cloud service account key", severity: "critical", re: /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key_id"\s*:\s*"[a-f0-9]{40}"/g },
  { id: "azure_storage_key", label: "Azure storage connection string", severity: "critical", re: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}/g },
  { id: "azure_sas", label: "Azure SAS token", severity: "high", re: /[?&]sv=\d{4}-\d{2}-\d{2}&[^\s"'<>]*?sig=[A-Za-z0-9%+/=]{30,}/g },

  // --- Source control, CI and SaaS tokens --------------------------------------
  { id: "github_token", label: "GitHub token", severity: "critical", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g },
  { id: "gitlab_token", label: "GitLab token", severity: "critical", re: /\bglpat-[A-Za-z0-9_\-]{20,}\b/g },
  { id: "slack_token", label: "Slack token", severity: "critical", re: /\bxox[abposr]-(?:\d+-)+[A-Za-z0-9]{10,}\b/g },
  { id: "slack_webhook", label: "Slack webhook URL", severity: "high", re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_\-]{20,}/g },
  { id: "discord_webhook", label: "Discord webhook URL", severity: "high", re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,20}\/[A-Za-z0-9_\-]{50,}/g },
  { id: "telegram_bot", label: "Telegram bot token", severity: "high", re: /\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b/g },
  { id: "teams_webhook", label: "Microsoft Teams webhook", severity: "high", re: /https:\/\/[a-z0-9\-]+\.webhook\.office\.com\/webhookb2\/[A-Za-z0-9@\-/]{50,}/g },
  { id: "stripe_secret", label: "Stripe secret key", severity: "critical", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
  { id: "stripe_test", label: "Stripe test secret key", severity: "medium", re: /\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b/g },
  { id: "openai_key", label: "OpenAI API key", severity: "critical", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b/g },
  { id: "anthropic_key", label: "Anthropic API key", severity: "critical", re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b/g },
  { id: "generic_sk", label: "Secret API key (sk-…)", severity: "high", re: /\bsk-[A-Za-z0-9]{32,}\b/g, minEntropy: 3.8 },
  { id: "google_oauth_secret", label: "Google OAuth client secret", severity: "high", re: /\bGOCSPX-[A-Za-z0-9_\-]{28}\b/g },
  { id: "twilio_key", label: "Twilio API key", severity: "high", re: /\bSK[0-9a-f]{32}\b/g },
  { id: "sendgrid_key", label: "SendGrid API key", severity: "critical", re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g },
  { id: "mailgun_key", label: "Mailgun API key", severity: "high", re: /\bkey-[0-9a-f]{32}\b/g },
  { id: "mailchimp_key", label: "Mailchimp API key", severity: "high", re: /\b[0-9a-f]{32}-us\d{1,2}\b/g },
  { id: "npm_token", label: "npm access token", severity: "critical", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "pypi_token", label: "PyPI token", severity: "critical", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b/g },
  { id: "shopify_token", label: "Shopify access token", severity: "critical", re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g },
  { id: "square_token", label: "Square access token", severity: "critical", re: /\bEAAA[A-Za-z0-9_\-]{60}\b|\bsq0atp-[A-Za-z0-9_\-]{22}\b/g },
  { id: "hf_token", label: "Hugging Face token", severity: "high", re: /\bhf_[A-Za-z]{34}\b/g },
  { id: "digitalocean_token", label: "DigitalOcean token", severity: "critical", re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g },
  { id: "heroku_key", label: "Heroku API key", severity: "high", re: /heroku.{0,20}?['"=:\s]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi, group: 1 },
  { id: "datadog_key", label: "Datadog API key", severity: "high", re: /(?:datadog|dd_api_key|DD_API_KEY).{0,20}?['"=:\s]([a-f0-9]{32})\b/gi, group: 1 },

  // --- Credentials in configuration ----------------------------------------------
  { id: "db_url", label: "Database URL with password", severity: "critical", re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/[^\s:@/"'<>]{1,64}:[^\s@/"'<>]{3,128}@[^\s"'<>]{3,}/gi },
  { id: "url_basic_auth", label: "Password in URL", severity: "high", re: /\bhttps?:\/\/[^\s:@/"'<>]{1,64}:[^\s@/"'<>]{3,128}@[a-z0-9.\-]+/gi },
  { id: "password_assignment", label: "Hard-coded password", severity: "high", re: /\b(?:password|passwd|pwd|db_pass(?:word)?|admin_pass(?:word)?|secret_key|client_secret|api_secret|app_secret)["']?\s*[:=]\s*["']([^"'\s]{6,100})["']/gi, group: 1, minEntropy: 2.5, reject: /^(?:\*+|•+|x+|password|changeme|yourpassword|your_password|null|undefined|true|false|none|example|placeholder|\$\{.*\}|<.*>|\{\{.*\}\}|%s|string|required|text|hidden)$/i },
  { id: "jwt", label: "JSON Web Token", severity: "medium", re: /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g },
  { id: "bearer", label: "Bearer token", severity: "medium", re: /\bBearer\s+([A-Za-z0-9_\-.=~+/]{30,})/g, group: 1, minEntropy: 3.5 },

  // --- Financial and personal data -------------------------------------------------
  { id: "iban", label: "IBAN", severity: "medium", re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g, validate: iban },
  { id: "fi_hetu", label: "Finnish personal identity code", severity: "high", re: /\b\d{6}[-+A-FU-Y]\d{3}[0-9A-Y]\b/g, validate: finnishHetu },
  { id: "us_ssn", label: "US Social Security number", severity: "high", re: /\b\d{3}-\d{2}-\d{4}\b/g, validate: usSsn },
  { id: "payment_card", label: "Payment card number", severity: "high", re: /\b(?:\d[ \-]?){12,18}\d\b/g, validate: (v) => luhn(v) && /^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5|4[4-9])|35|3(?:0[0-5]|[68])|62)/.test(v.replace(/\D/g, "")) }
];

/**
 * Decode a JWT's header and payload (no signature check: we only want to know
 * what it reveals: issuer, subject, e-mail, expiry).
 */
export function decodeJwt(token) {
  const [h, p] = String(token).split(".");
  const dec = (s) => {
    try {
      const b = s.replace(/-/g, "+").replace(/_/g, "/");
      const json = decodeURIComponent(
        Array.from(atob(b + "===".slice((b.length + 3) % 4)), (c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")
      );
      return JSON.parse(json);
    } catch {
      return null;
    }
  };
  const header = dec(h);
  const payload = dec(p);
  if (!header || !payload) return null;
  const exp = typeof payload.exp === "number" ? new Date(payload.exp * 1000).toISOString() : null;
  return {
    header,
    payload,
    alg: header.alg,
    issuer: payload.iss,
    subject: payload.sub,
    email: payload.email,
    expires: exp,
    expired: exp ? Date.parse(exp) < Date.now() : null
  };
}

/**
 * Run all detectors over `text`.
 * @param {string} text
 * @param {object} [o]
 * @param {string} [o.source]        label for where the text came from
 * @param {number} [o.maxPerDetector=25]
 * @returns {Array<{id,label,severity,value,masked,context,source,extra}>}
 */
export function scanExposures(text, o = {}) {
  if (!text) return [];
  const max = o.maxPerDetector ?? 25;
  const claimed = []; // [start, end) ranges already matched
  const overlaps = (s, e) => claimed.some(([a, b]) => s < b && e > a);
  const out = [];
  for (const d of DETECTORS) {
    const seen = new Set();
    let n = 0;
    for (const m of text.matchAll(d.re)) {
      const value = d.group ? m[d.group] : m[0];
      if (!value) continue;
      const start = d.group ? m.index + m[0].indexOf(value) : m.index;
      const end = start + value.length;
      if (overlaps(start, end)) continue;
      if (d.validate && !d.validate(value)) continue;
      if (d.minEntropy && entropy(value) < d.minEntropy) continue;
      if (d.reject && d.reject.test(value)) continue;
      const key = value.replace(/\s+/g, "").toLowerCase();
      claimed.push([start, end]);
      if (seen.has(key)) continue;
      seen.add(key);
      const extra = {};
      if (d.id === "payment_card") extra.brand = cardBrand(value);
      if (d.id === "jwt") {
        const j = decodeJwt(value);
        if (j) Object.assign(extra, { alg: j.alg, issuer: j.issuer, subject: j.subject, email: j.email, expires: j.expires, expired: j.expired });
      }
      out.push({
        id: d.id,
        label: d.label,
        severity: d.severity,
        value: value.length > 600 ? `${value.slice(0, 600)}…` : value,
        masked: mask(value.length > 80 ? value.slice(0, 80) : value),
        context: contextOf(text, start, value.length),
        source: o.source || "text",
        extra
      });
      if (++n >= max) break;
    }
  }
  return out;
}

/** Query-string parameter names that usually carry credentials. */
const SECRET_PARAM = /^(?:access_?token|id_?token|refresh_?token|auth_?token|token|api_?key|apikey|key|secret|client_?secret|password|passwd|pwd|pass|session(?:id)?|sid|credential|signature|sig|x-amz-signature|x-amz-credential|x-goog-signature|auth|code|jwt|private_?token|sas)$/i;

/** Credentials carried in URLs (signed URLs, ?token=, ?api_key=). */
export function urlSecrets(href) {
  let u;
  try {
    u = new URL(href);
  } catch {
    return [];
  }
  const out = [];
  for (const [k, v] of u.searchParams) {
    if (SECRET_PARAM.test(k) && v && v.length >= 8 && !/^\{.*\}$|^\$|^(true|false|null|undefined)$/i.test(v)) {
      out.push({ param: k, value: v });
    }
  }
  if (u.password) out.push({ param: "(URL password)", value: u.password });
  return out;
}
