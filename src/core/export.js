// Report exporters: JSON, Markdown, CSV (indicators) and STIX 2.1 (for threat
// intelligence platforms such as OpenCTI and MISP). Pure functions.

import { INDICATOR_TYPES } from "./indicators.js";

const md = (s) => String(s ?? "").replace(/([\\`*_{}[\]<>|])/g, "\\$1").replace(/\n+/g, " ");

export function toJson(report) {
  return JSON.stringify(report, null, 2);
}

/** CSV with one row per indicator. */
export function toCsv(report) {
  const esc = (v) => {
    const s = String(v ?? "");
    return /[",\n\r]/.test(s) || /^[=+\-@\t]/.test(s) ? `"${(/^[=+\-@\t]/.test(s) ? `'${s}` : s).replace(/"/g, '""')}"` : s;
  };
  const rows = [["type", "value", "label", "confidence", "count", "sources", "page_url", "scanned_at"]];
  for (const i of report.indicators || []) rows.push([i.type, i.value, i.label || "", i.confidence, i.count, (i.sources || []).join("; "), report.page.url, report.createdAt]);
  return rows.map((r) => r.map(esc).join(",")).join("\r\n");
}

/** Human-readable Markdown report. */
export function toMarkdown(report) {
  const L = [];
  const p = report.page;
  L.push(`# OSINT Lens report: ${md(p.title || p.host)}`, "");
  L.push(`- **URL:** ${md(p.url)}`, `- **Site:** ${md(p.site)}${p.unicodeHost ? ` (displays as ${md(p.unicodeHost)})` : ""}`, `- **Scanned:** ${report.createdAt}`);
  if (report.phishing) L.push(`- **Phishing heuristics:** ${report.phishing.score}/100 (${report.phishing.level})`);
  if (report.headers) L.push(`- **Security headers grade:** ${report.headers.grade}`);
  if (report.favicon) L.push(`- **Favicon hash (mmh3):** ${report.favicon.mmh3}`);
  L.push("");

  const ai = report.ai?.result;
  if (ai) {
    L.push("## AI analysis", "", `**${md(ai.verdict || "")}** (risk: ${md(ai.risk_level || "?")}, model: ${md(report.ai.model)})`, "", md(ai.summary || ""), "");
    if (ai.attribution) L.push(`**Attribution:** ${md(ai.attribution)}`, "");
    for (const f of ai.key_findings || []) L.push(`- **[${md(f.severity)}] ${md(f.title)}**: ${md(f.detail)}${f.evidence ? ` — \`${md(f.evidence)}\`` : ""}`);
    if (ai.pivots?.length) {
      L.push("", "**Suggested pivots**", "");
      for (const pv of ai.pivots) L.push(`- ${md(pv.indicator)}: ${md(pv.why)} (${md(pv.how)})`);
    }
    L.push("");
  }

  if (report.phishing?.signals?.length) {
    L.push("## Phishing signals", "");
    for (const s of report.phishing.signals) L.push(`- (+${s.weight}) ${md(s.title)}${s.detail ? `: ${md(s.detail)}` : ""}`);
    L.push("");
  }

  if (report.exposures?.length) {
    L.push("## Possible exposures", "", "| Severity | Type | Value (masked) | Where |", "|---|---|---|---|");
    for (const e of report.exposures) L.push(`| ${e.severity} | ${md(e.label)} | \`${md(e.masked)}\` | ${md(e.source)} |`);
    L.push("");
  }

  const groups = {};
  for (const i of report.indicators || []) (groups[i.type] ||= []).push(i);
  if (Object.keys(groups).length) {
    L.push("## Indicators", "");
    for (const [type, list] of Object.entries(groups)) {
      L.push(`### ${INDICATOR_TYPES[type] || type} (${list.length})`, "");
      for (const i of list.slice(0, 300)) L.push(`- \`${md(i.value)}\`${i.label ? ` — ${md(i.label)}` : ""}${i.sources?.length ? ` _(${md(i.sources.slice(0, 3).join(", "))})_` : ""}`);
      L.push("");
    }
  }

  if (report.tech?.length) {
    L.push("## Technologies", "");
    for (const t of report.tech) L.push(`- ${md(t.name)}${t.version ? ` ${md(t.version)}` : ""} (${md(t.cat)})${t.vulns.length ? ` — **outdated**: ${t.vulns.map((v) => md(v.summary)).join("; ")}` : ""}`);
    L.push("");
  }

  const on = report.online;
  if (on) {
    L.push("## Infrastructure", "");
    if (on.rdap?.found) L.push(`- Registered ${on.rdap.created || "?"} via ${md(on.rdap.registrar || "?")}, expires ${on.rdap.expires || "?"}`);
    if (on.dns) {
      L.push(`- A: ${on.dns.A.join(", ") || "—"}`, `- NS: ${on.dns.NS.join(", ") || "—"}`, `- MX: ${on.dns.MX.join(", ") || "—"}`);
    }
    if (on.mail) L.push(`- Mail: SPF ${on.mail.spf ? `\`${md(on.mail.spf)}\`` : "none"}, DMARC ${on.mail.dmarcPolicy || "none"}`);
    for (const ip of on.ips || []) L.push(`- ${ip.ip}: ${ip.asn ? `AS${ip.asn.asn} ${md(ip.asn.name)}` : ""}${ip.internetdb?.ports?.length ? `, ports ${ip.internetdb.ports.join(", ")}` : ""}`);
    if (on.ct) L.push(`- ${on.ct.subdomains.length} names in certificate transparency`);
    if (on.wayback) L.push(`- Archived since ${on.wayback.firstSeen || "?"}`);
    L.push("");
  }

  if (report.files?.length) {
    L.push("## File metadata", "");
    for (const f of report.files) {
      L.push(`### ${md(f.url)}`, "", `SHA-256 \`${f.sha256 || "?"}\`${f.error ? ` — error: ${md(f.error)}` : ""}`, "");
      for (const r of (f.rows || []).slice(0, 40)) L.push(`- ${r.sensitive ? "**" : ""}${md(r.name)}${r.sensitive ? "**" : ""}: ${md(r.value)}`);
      L.push("");
    }
  }

  if (report.evidence?.length) {
    L.push("## Evidence", "");
    for (const e of report.evidence) L.push(`- ${e.kind} captured ${e.capturedAt}, SHA-256 \`${e.sha256}\``);
    L.push("");
  }
  if (report.notes) L.push("## Notes", "", report.notes, "");
  L.push("---", `Generated by OSINT Lens. Heuristic findings are leads, not conclusions; verify before acting.`);
  return L.join("\n");
}

// ---------------------------------------------------------------------------
// STIX 2.1
// ---------------------------------------------------------------------------

/** Deterministic UUIDv5-style id from a string (so re-exports produce the same ids). */
async function stixId(type, key) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(`osint-lens|${type}|${key}`))).slice(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const h = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${type}--${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** STIX 2.1 bundle: observables (SCOs) for indicators plus a report object tying them together. */
export async function toStix(report) {
  const now = new Date().toISOString();
  const objects = [];
  const refs = [];
  const identity = { type: "identity", spec_version: "2.1", id: await stixId("identity", "osint-lens"), created: "2024-01-01T00:00:00.000Z", modified: "2024-01-01T00:00:00.000Z", name: "OSINT Lens", identity_class: "system" };
  objects.push(identity);
  const add = async (type, key, props) => {
    const id = await stixId(type, key);
    if (objects.some((o) => o.id === id)) return id;
    objects.push({ type, spec_version: "2.1", id, ...props });
    refs.push(id);
    return id;
  };
  for (const i of report.indicators || []) {
    const v = String(i.value);
    switch (i.type) {
      case "domain":
      case "host":
        await add("domain-name", v.toLowerCase(), { value: v.toLowerCase() });
        break;
      case "ip":
        await add(v.includes(":") ? "ipv6-addr" : "ipv4-addr", v, { value: v });
        break;
      case "email":
        await add("email-addr", v.toLowerCase(), { value: v.toLowerCase() });
        break;
      case "url":
      case "social":
        await add("url", v, { value: v });
        break;
      case "asn":
        await add("autonomous-system", v, { number: Number(v.replace(/^AS/i, "")), ...(i.label ? { name: i.label } : {}) });
        break;
      case "hash":
        await add("file", v, { hashes: { [i.label === "MD5" ? "MD5" : i.label === "SHA-1" ? "SHA-1" : "SHA-256"]: v } });
        break;
      case "cve":
        await add("vulnerability", v, { created: now, modified: now, name: v, external_references: [{ source_name: "cve", external_id: v }] });
        break;
      case "organization":
        await add("identity", `org|${v}`, { created: now, modified: now, name: v, identity_class: "organization" });
        break;
      case "person":
        await add("identity", `person|${v}`, { created: now, modified: now, name: v, identity_class: "individual" });
        break;
      default:
        break;
    }
  }
  // Identifiers with no STIX 2.1 core object (tracker IDs, wallets, phones...) go into a note so nothing is lost.
  const custom = (report.indicators || []).filter((i) => ["tracker", "verification", "api_key_public", "favicon", "phone", "crypto", "coordinates", "onion", "handle", "bucket", "business_id", "iban", "address"].includes(i.type));
  if (custom.length) {
    const id = await stixId("note", `${report.id}|custom`);
    objects.push({ type: "note", spec_version: "2.1", id, created: now, modified: now, created_by_ref: identity.id, abstract: "Additional identifiers", content: custom.map((i) => `${i.type}${i.label ? ` (${i.label})` : ""}: ${i.value}`).join("\n"), object_refs: refs.length ? refs.slice(0, 1) : [identity.id] });
    refs.push(id);
  }
  const url = await add("url", report.page.url, { value: report.page.url });
  const rep = {
    type: "report",
    spec_version: "2.1",
    id: await stixId("report", report.id),
    created: report.createdAt,
    modified: now,
    created_by_ref: identity.id,
    name: `OSINT Lens: ${report.page.title || report.page.host}`,
    description: [report.ai?.result?.summary, report.phishing ? `Phishing heuristics ${report.phishing.score}/100 (${report.phishing.level}).` : null].filter(Boolean).join(" ") || `Web page scan of ${report.page.url}`,
    report_types: [report.phishing?.level === "high" ? "threat-report" : "observed-data"],
    published: now,
    object_refs: [...new Set([url, ...refs])]
  };
  objects.push(rep);
  return JSON.stringify({ type: "bundle", id: await stixId("bundle", `${report.id}|${now}`), objects: objects.map((o) => JSON.parse(JSON.stringify(o))) }, null, 2);
}
