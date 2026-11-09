# Changelog

## 2.0.0 — OSINT Lens

A complete rewrite of the v1 "Sensitive Data Scanner" into an OSINT workbench.

### Added
- Side panel UI with Overview, Indicators, Exposures, Infrastructure, Tech & trackers, Links & forms, Files, AI and MCP tabs, plus Lookup, History and a pop-out mode.
- Entity extraction for 20+ indicator types with checksum validation (crypto wallets, IBAN, business IDs…).
- 72 tracking/advertising/account-ID rules, verification tokens from meta tags and DNS, `ads.txt` seller accounts.
- 143 technology fingerprints with versions and known-vulnerable ranges.
- Security-header grading, CSP host extraction and infrastructure-leak detection.
- JavaScript intelligence: endpoints, buckets, internal and pre-production hosts, source maps, env variables, comments.
- Phishing and scam triage with explained, weighted signals (homographs, brand impersonation, form exfiltration, drainers, ClickFix…).
- Favicon fingerprints (Shodan MurmurHash3, MD5, SHA-256).
- File metadata: EXIF/GPS, XMP, IPTC, PDF, OOXML and ODF.
- Online lookups: DNS over HTTPS, mail security, RDAP, ASN, Shodan InternetDB, certificate transparency, Wayback Machine, urlscan.io, GTM containers.
- AI providers: Ollama (kept and improved), OpenAI-compatible servers and Anthropic. Three analysis modes, custom questions, follow-ups, tool calling.
- MCP client supporting the 2026-07-28 stateless Streamable HTTP, the 2025 handshake/session transport and legacy HTTP+SSE; per-server approval policies; recipes; a zero-dependency stdio bridge.
- Local history in IndexedDB with cross-investigation correlation, relationship graph, notes, tags and stars.
- Evidence capture (screenshot, MHTML) with SHA-256; exports to Markdown, JSON, CSV and STIX 2.1.
- Context menus and keyboard shortcuts.
- Unit tests, a browser end-to-end test, static checks, CI and a packaging script.

### Kept from v1
- The pattern-plus-checksum exposure scanning, masking, on-page highlighting and Ollama support, all reworked.
