# Research notes: what makes good webpage OSINT

These notes record the research behind OSINT Lens 2.0: what investigators actually pivot on, what a single web page can reveal, and how each finding maps to a feature. Sources are listed at the end.

## 1. Principles

1. **Prefer identifiers that belong to an account over ones that belong to infrastructure.** A shared IP often means only a shared host or CDN. A shared Google Analytics, AdSense, Meta Pixel or Sentry account ID means a shared owner. Practitioner guides consistently put unique identifiers above shared public IPs for linking sites. → *Tracker IDs are marked "links sites", correlation ranks them first, and IDs are also pulled from runtime state and inside GTM containers.*
2. **Combine weak signals.** A matching favicon plus a matching certificate is stronger than either alone. Phishing research reaches the same conclusion: no single heuristic is reliable, so many weak signals are weighed together. → *Explained, weighted phishing signals instead of a black-box verdict; a relationship graph across investigations.*
3. **Stay passive by default.** Reading what a page serves, querying public datasets (CT logs, passive DNS, archives) and resolving DNS through public resolvers doesn't touch the target beyond normal browsing. Requesting unlinked paths such as `/.git` or `/.env` is active probing, and most methodologies require authorisation for it. → *The extension reads only conventional public files (`robots.txt`, `security.txt`, `ads.txt`…) and what the page references. It never guesses paths.*
4. **Keep evidence.** Pages change and disappear. Investigations need captures with hashes and timestamps. → *Screenshot and MHTML evidence with SHA-256; links to the Wayback Machine and archive.today.*
5. **Treat the analyst's tooling as an attack surface.** Pivot services log queries, and LLMs can be steered by hostile content. → *Nothing is sent until you choose it; the privacy doc lists every flow; MCP tool approvals; secrets masked for remote AI.*

## 2. What a single page reveals

### Ownership and linkage
- **Analytics, ad and tag IDs** (GA4 `G-`, legacy `UA-`, `GTM-`, AdSense `ca-pub-`, AW-, Meta Pixel, TikTok, LinkedIn Insight, Hotjar, Clarity, Yandex Metrica…). These can be reverse-searched in source-code search engines (PublicWWW) and reverse-analytics services (DNSlytics, SpyOnWeb, BuiltWith relationships). The Bellingcat *wayback-google-analytics* project shows that historic IDs matter as much as current ones.
- **Site-verification tokens** in meta tags and DNS TXT records (Google Search Console, Microsoft 365, Meta, Apple, Atlassian…). They are per-account and searchable.
- **ads.txt / app-ads.txt** `DIRECT` entries list the publisher's own ad accounts.
- **Structured data** (JSON-LD `Organization`/`Person`, `sameAs`, `vatID`, founders), `rel=me`, meta author, social cards.
- **Favicons**: MurmurHash3 of the base64-encoded icon (Shodan `http.favicon.hash`, FOFA `icon_hash`) finds sibling servers, origins behind CDNs and copies of phishing kits. Default framework icons are noise.

### Infrastructure
- **Certificate transparency** (crt.sh, Censys, Cert Spotter) reveals subdomains and naming patterns without scanning.
- **DNS**: A/AAAA, NS, MX (mail provider), TXT (verification and SPF includes that name the services the company uses), DMARC report addresses.
- **RDAP/WHOIS**: registration age (very young domains are a strong phishing indicator), registrar, and the registrant when it isn't redacted.
- **ASN and hosting** tell you whether the visible IP is a CDN (the real origin is hidden) or the actual host. **InternetDB** gives open ports and known CVEs without scanning.
- **Response headers** leak servers, versions, backend names and internal IPs. A CSP lists every service the site may talk to.
- **Archives** (Wayback CDX) show history, first-seen date and documents that have since been removed.

### Exposure
- **Secrets in client code**: cloud keys, tokens, database URLs, webhooks, build-time env variables, source maps that give away the original source.
- **Cloud storage buckets** and **internal or pre-production hostnames** referenced in JavaScript.
- **Developer comments** in HTML and JS.
- **robots.txt** often lists the paths an admin wants hidden.
- **Document and image metadata**: authors, user names inside paths, company, software, GPS, camera serial numbers, edit history and document IDs that link derivative files.

### Phishing and scam triage
Signals from academic and practitioner work: a password form posting to another domain; punycode and mixed-script (homograph) domains, normalised before comparison; brand names or typos of brands in the host; brand assets loaded from the brand's own servers; newly registered domains; cheap, abused TLDs; free-hosting and tunnelling subdomains; urgency language; forms posting to messaging APIs (Telegram bots, Discord webhooks); and newer patterns such as wallet drainers, seed-phrase requests and "ClickFix" fake CAPTCHAs that put a command on the clipboard.

## 3. Why MCP and local AI

- **Local models (Ollama)** let you analyse sensitive pages without sending them anywhere. Testing for this release showed that small models (e.g. qwen3 8B) call tools much more reliably with thinking enabled, so it's on by default.
- **MCP** turns any lookup service or internal system into a tool, without OSINT Lens having to integrate each API itself. The 2026-07-28 specification made Streamable HTTP stateless (no initialize handshake or session ID; version and capabilities in each request's `_meta`). Many servers still speak the 2025 handshake or the 2024 SSE transport, so the client supports all three. Browser extensions can't spawn processes, which is why stdio servers go through a bridge.
- The **security guidance** in the MCP specification (validate `Origin`, bind locally, authenticate, treat tool annotations from untrusted servers as untrusted) shaped the bridge and the approval policies.

## 4. Feature mapping (v1 → v2)

| v1 (Sensitive Data Scanner) | v2 (OSINT Lens) |
|---|---|
| 15 regex detectors | 41 exposure detectors, plus entity extraction with checksums for 20+ indicator types |
| Link list by extension | Links, forms, frames, scripts, third-party map, CSP hosts |
| Ollama only, one prompt | Ollama, OpenAI-compatible and Anthropic; 3 modes plus custom questions and follow-ups; tool calling |
| — | MCP client (3 transports), stdio bridge, recipes, approvals |
| — | Online lookups (8 free sources), favicon hashes, file metadata, tech fingerprinting, phishing triage |
| Results lost on navigation | Local history, cross-investigation correlation, graph, notes, evidence, STIX/Markdown/CSV export |
| Popup | Persistent side panel, pop-out tab, context menus, keyboard shortcuts |

## Sources

- osintme.com, *The importance of favicons in website OSINT research*, https://osintme.com/index.php/2025/01/20/the-importance-of-favicons-in-website-osint-research/
- enetolabs, *Investigating infrastructure that hides behind Cloudflare using OSINT*, https://enetolabs.medium.com/investigating-infrastructure-that-hides-behind-cloudflare-using-osint-a2e3479e4f58
- ransomnews.com, *Hunting C2 infrastructure: favicon, JARM, cert logs*, https://ransomnews.com/hunt-threat-infrastructure-favicon-jarm-2026/
- visualnotes.tech, *Domain Investigation OSINT Workflow (2026)*, https://www.visualnotes.tech/blog/how-to-investigate-a-domain-osint-workflow
- usersearch.com, *Domain OSINT & Infrastructure Guide*, https://usersearch.com/resources/intel-hub/blog/domain-osint-whois-infrastructure/
- Bellingcat, *wayback-google-analytics*, https://github.com/bellingcat/wayback-google-analytics
- Indicator, *Investigating websites*, https://indicator.media/t/investigating-websites
- Shodan, *Introducing the InternetDB API*, https://blog.shodan.io/introducing-the-internetdb-api/
- *PhishMatch: A Layered Approach for Effective Detection of Phishing URLs*, https://arxiv.org/pdf/2112.02226
- ipthreat.net, *Rebuilding phishing URL detection from first principles*, https://ipthreat.net/blog/when-the-fake-fifa-ticket-site-cleared-every-filter-rebuilding-phishing-url-detection-from-first-principles-84
- Passive reconnaissance guides: https://tharunaditya.github.io/blog/2026/02/09/pentesting-02-passive-recon, https://ngtuonghung.github.io/blog/cheatsheets/web-recon
- Model Context Protocol specification 2026-07-28: transports, versioning, tools, authorization and schema, https://modelcontextprotocol.io/specification/2026-07-28/ and legacy revisions 2025-11-25 and 2024-11-05
- Ollama, *Thinking* and tool-calling documentation, https://ollama.com/blog/thinking
- Chrome, *Offscreen documents in Manifest V3* and extension service worker lifetime, https://developer.chrome.com/blog/Offscreen-Documents-in-Manifest-v3
