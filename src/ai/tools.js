// Built-in tools the AI can call during an analysis. All are read-only.
// Network tools use the same public sources as the "Online lookups" step and
// are only offered when that source is enabled in settings.

import { resolve, reverseDns } from "../intel/dns.js";
import { rdapDomain, rdapIp } from "../intel/rdap.js";
import { certTransparency, wayback, internetDb, asnLookup, urlscanSearch } from "../intel/sources.js";

const str = (desc) => ({ type: "string", description: desc });
const obj = (properties, required) => ({ type: "object", properties, required, additionalProperties: false });

/**
 * @param {object} report    the current report (read by report_section / search_page_text)
 * @param {object} online    settings.online (which sources are allowed)
 */
export function builtinTools(report, online) {
  const tools = [
    {
      name: "report_section",
      description: "Get the full data for one section of the current page report as JSON. Sections: indicators, exposures, trackers, tech, headers, links, third_parties, forms, js, comments, well_known, online, files, images, scripts, identity, meta, mcp.",
      parameters: obj({ section: str("section name"), type: str("for indicators: optional indicator type filter, e.g. email, tracker, domain") }, ["section"]),
      readOnly: true,
      run: async ({ section, type }) => {
        const map = { third_parties: "thirdParties", well_known: "wellKnown" };
        let data = report[map[section] || section];
        if (section === "indicators" && type) data = (data || []).filter((i) => i.type === type);
        if (data === undefined) return `Unknown section "${section}".`;
        return JSON.stringify(data).slice(0, 15000);
      }
    },
    {
      name: "search_page_text",
      description: "Search the page's visible text for a word or phrase (case-insensitive). Returns up to 15 snippets with context.",
      parameters: obj({ query: str("text to find") }, ["query"]),
      readOnly: true,
      run: async ({ query }) => {
        const text = report.content?.text || "";
        const q = String(query || "").toLowerCase();
        if (!q) return "Empty query.";
        const out = [];
        let i = text.toLowerCase().indexOf(q);
        while (i >= 0 && out.length < 15) {
          out.push(`…${text.slice(Math.max(0, i - 120), i + q.length + 120).replace(/\s+/g, " ")}…`);
          i = text.toLowerCase().indexOf(q, i + q.length);
        }
        return out.length ? out.join("\n") : "No matches.";
      }
    }
  ];
  if (online.dns) {
    tools.push({
      name: "dns_lookup",
      description: "Resolve DNS records through a public DNS-over-HTTPS resolver. Types: A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, PTR (for PTR pass an IP as name).",
      parameters: obj({ name: str("domain name or IP (for PTR)"), type: { type: "string", enum: ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "PTR"] } }, ["name", "type"]),
      readOnly: true,
      run: async ({ name, type }) => JSON.stringify(type === "PTR" ? await reverseDns(name) : await resolve(name, type))
    });
  }
  if (online.rdap) {
    tools.push({
      name: "rdap_domain",
      description: "Registration data for a domain (RDAP/WHOIS): registrar, creation/expiry dates, status, name servers, registrant if published.",
      parameters: obj({ domain: str("registrable domain, e.g. example.com") }, ["domain"]),
      readOnly: true,
      run: async ({ domain }) => JSON.stringify(await rdapDomain(domain))
    });
    tools.push({
      name: "rdap_ip",
      description: "Registration data for an IP address: network name, owner organisation, range, country, abuse contact.",
      parameters: obj({ ip: str("IPv4 or IPv6 address") }, ["ip"]),
      readOnly: true,
      run: async ({ ip }) => JSON.stringify(await rdapIp(ip))
    });
  }
  if (online.asn) {
    tools.push({
      name: "asn_lookup",
      description: "Map an IP address to its autonomous system (network operator / hosting provider).",
      parameters: obj({ ip: str("IP address") }, ["ip"]),
      readOnly: true,
      run: async ({ ip }) => JSON.stringify(await asnLookup(ip))
    });
  }
  if (online.internetdb) {
    tools.push({
      name: "open_ports",
      description: "Shodan InternetDB: open ports, detected software (CPEs), known CVEs and tags for an IP. Data is refreshed weekly.",
      parameters: obj({ ip: str("IPv4 address") }, ["ip"]),
      readOnly: true,
      run: async ({ ip }) => JSON.stringify((await internetDb(ip)) || "No data for this IP.")
    });
  }
  if (online.ct) {
    tools.push({
      name: "subdomains_from_certificates",
      description: "List subdomains seen in public TLS certificate transparency logs for a domain.",
      parameters: obj({ domain: str("registrable domain") }, ["domain"]),
      readOnly: true,
      run: async ({ domain }) => {
        const r = await certTransparency(domain);
        return JSON.stringify({ ...r, subdomains: r.subdomains.slice(0, 300) });
      }
    });
  }
  if (online.wayback) {
    tools.push({
      name: "archive_history",
      description: "Wayback Machine history for a host: first and last capture dates, number of archived URLs, archived documents and data files.",
      parameters: obj({ host: str("hostname") }, ["host"]),
      readOnly: true,
      run: async ({ host }) => JSON.stringify(await wayback(host)).slice(0, 12000)
    });
  }
  if (online.urlscan) {
    tools.push({
      name: "urlscan_history",
      description: "Previous public urlscan.io scans of a domain: dates, URLs, IPs, ASNs, page titles.",
      parameters: obj({ domain: str("domain") }, ["domain"]),
      readOnly: true,
      run: async ({ domain }) => JSON.stringify(await urlscanSearch(domain, { apiKey: online.urlscanKey })).slice(0, 12000)
    });
  }
  return tools.map((t) => ({ ...t, source: "built-in" }));
}
