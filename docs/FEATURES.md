# OSINT Lens feature guide

Everything the extension does, what each feature is for, and what to know about it: in general and from a security point of view. For the internals see [HOW_IT_WORKS.md](HOW_IT_WORKS.md); for every data flow see [PRIVACY.md](PRIVACY.md); for MCP setup see [MCP.md](MCP.md).

## Contents

1. [Getting around](#1-getting-around)
2. [Scanning a page](#2-scanning-a-page)
3. [Overview tab](#3-overview-tab)
4. [Indicators](#4-indicators)
5. [Exposures](#5-exposures)
6. [Infrastructure](#6-infrastructure)
7. [Tech & trackers](#7-tech--trackers)
8. [Links & forms](#8-links--forms)
9. [Files (metadata)](#9-files-metadata)
10. [Phishing and scam triage](#10-phishing-and-scam-triage)
11. [Online lookups](#11-online-lookups)
12. [AI analysis](#12-ai-analysis)
13. [MCP tools](#13-mcp-tools)
14. [Lookup](#14-lookup)
15. [History and correlation](#15-history-and-correlation)
16. [Evidence capture](#16-evidence-capture)
17. [Exports](#17-exports)
18. [Settings](#18-settings)
19. [Permissions and site access](#19-permissions-and-site-access)
20. [Security model](#20-security-model)
21. [Operational security for investigators](#21-operational-security-for-investigators)
22. [Reading the results: confidence and false positives](#22-reading-the-results-confidence-and-false-positives)
23. [Reference: the MCP bridge](#23-reference-the-mcp-bridge)

---

## 1. Getting around

| Element | What it does |
|---|---|
| **Toolbar icon** / <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>O</kbd> | Opens the side panel. The panel stays open while you browse and follows the active tab. |
| **Scan page** / <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd> | Reads the current page and builds a report (usually under two seconds). |
| **Tab bar** | Overview, Indicators, Exposures, Infrastructure, Tech & trackers, Links & forms, Files, AI, MCP. Counts show how much each tab holds. |
| **Lookup** | Investigate any value you paste or right-click, without scanning a page. |
| **History** | Earlier reports, searchable by URL, title, tag or any indicator value. |
| **⧉ Pop-out** | Opens the panel as a full browser tab bound to the page you were on. Useful on small screens and for long reports. |
| **⚙ Settings** | AI providers, MCP servers, recipes, scanning options, online sources, privacy. |
| **Right-click menu** | *Scan this page*, *Investigate "selected text"*, *Investigate this link*, *Check this image's metadata*. |

**Good to know**

- Closing the panel never cancels work. Scans, lookups and AI analyses run in the extension's background worker; reopen the panel to see the result.
- When the page changes under a report, the panel shows *The page has changed since this report was made* with a *Scan again* button. The old report stays in History.
- Everything on screen that came from the page or from a model is shown as plain text. Nothing a page says can run inside the panel.

---

## 2. Scanning a page

A scan reads the page as your browser has it right now, including content loaded by JavaScript, text inside open shadow roots and same-origin frames. It then requests a handful of conventional public files from the site, analyses everything locally and stores a report on your computer.

**What a scan reads from the page**

- Title, language, meta and link tags, structured data (JSON-LD), social sharing tags
- All links, scripts, stylesheets, frames, images, media, forms, HTML comments
- The network requests the page made while loading (URLs only, from the browser's Performance API)
- Cookie names and web-storage key names (never values)
- JavaScript globals, for framework versions and tag-manager state (a small read-only probe)
- Behaviour signals: blocked right-click, developer-tools detection, obfuscated scripts, meta refreshes, full-page frames, wallet-connect prompts, clipboard writes

**What a scan fetches from the site** (each can be turned off in Settings → Scanning)

- The page itself again, to read its response headers
- `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, `ads.txt`, `app-ads.txt`, the web-app manifest
- The site's own script files (up to 40 by default) and its favicon

These are the files any browser or crawler requests. The scan never guesses hidden paths such as `/.git` or `/admin`.

**Security notes**

- Password field values are never read. Other typed form values are read only if you enable *Scan values typed into form fields*; they're useful for checking what a form would send but they are, by definition, your data.
- The collector runs in Chrome's isolated world, so the page's own scripts can't see it or tamper with it. The only code that runs in the page's own world is the read-only probe.
- Requests made during a scan carry no cookies and no referrer.
- Pages the browser protects (`chrome://`, the Web Store, the PDF viewer) can't be scanned by any extension. Local `file://` pages need *Allow access to file URLs* on `chrome://extensions`.

---

## 3. Overview tab

The summary card at the top of every tab shows the page, the phishing score, counts, and the action buttons (*Online lookups*, *AI analysis*, *Evidence*, *Export*).

| Section | Purpose |
|---|---|
| **Highlights** | The findings most worth a look, ranked by severity: exposed secrets, strong phishing signals, outdated software, account-level IDs that can link the site to others, internal hosts in JavaScript, source maps, buckets, files worth checking, developer comments, weak headers, mail-security problems, young domains, interesting `robots.txt` paths, and the AI verdict when there is one. Each line links to the tab with the details. |
| **Seen in your earlier investigations** | Other sites in your History that share an identifier with this one, ordered by how strongly that identifier links owners (tracker IDs and verification tokens first). Click a site to open its report. |
| **Identity** | Who the site says it is: organisations and people from structured data (name, legal name, VAT ID, address, email, phone, founders, `sameAs` profiles), the domain registrant from RDAP when published, names found anywhere, site name, description, author, canonical URL, generator, `rel=me` links, feeds and language versions. |
| **Relationship graph** | The site in the middle, its identifiers around it, and earlier investigations connected through shared identifiers. Click a node for pivots or to open the other report. |
| **Quick facts** | Domain age, registrar, hosting, mail provider, CMS, server/CDN, first archive date, third-party count, page size, frames. |
| **Notes** | Free-text notes, tags and a *keep* star for this report, saved locally. |

**Good to know:** a canonical URL on a *different* site is flagged, because cloned pages often keep the original's canonical tag.

---

## 4. Indicators

Every identifier found on the page, de-duplicated, with where it was found, how often, and a confidence level. Filter by type or text, hide low-confidence items, copy, locate on the page (⌖) or open the **Pivot ▾** menu.

| Type | Examples and notes |
|---|---|
| Domain, Hostname, URL | The site, outbound-link domains, third-party sites, hosts named in the Content-Security-Policy, subdomains from certificate logs |
| IP address | From the page text, DNS results and scan history. Private/reserved ranges are marked. |
| Email | Plain addresses and obfuscated ones (`name [at] domain [dot] com`). Placeholders such as `example@example.com` are low confidence. |
| Phone | International `+…` numbers anywhere; national formats only after a label such as *Tel:* |
| Social profile | 60+ platforms: X, Facebook, Instagram, Threads, LinkedIn, YouTube, TikTok, GitHub, GitLab, Reddit, Telegram, WhatsApp, Signal, Discord, Mastodon and other fediverse servers, Bluesky, Pinterest, Snapchat, Twitch, Medium, Substack, VK, Patreon, Linktree, Keybase, Steam, Crunchbase, Gravatar and more |
| Handle / username | `@handles` in text (low confidence) and OS user names recovered from file paths |
| Crypto wallet | Bitcoin (legacy, SegWit, Taproot), Ethereum/EVM, Litecoin, Dogecoin, Tron, Monero, Bitcoin Cash, Cardano, Cosmos, Solana. Addresses with a checksum are validated, so a random string that looks like an address isn't reported. |
| Onion / I2P service | Tor v3 and I2P hostnames |
| Coordinates | Decimal pairs, degrees-minutes-seconds, map links (Google, Apple, OSM, Bing, Waze), EXIF GPS from photos, structured-data `geo` |
| Postal address | From structured data and RDAP |
| Tracking / ad ID | See [Tech & trackers](#7-tech--trackers) |
| Site verification token | Google Search Console, Bing, Yandex, Meta, Pinterest, Apple, Atlassian, Zoom, DocuSign and others, from meta tags and DNS TXT records |
| Favicon hash | MurmurHash3 as used by Shodan and FOFA |
| ASN | The autonomous systems of the site's IPs |
| File hash | MD5/SHA-1/SHA-256 strings on the page (low confidence) and the SHA-256 of files you analysed |
| CVE | CVE IDs on the page, from outdated software versions, and from Shodan InternetDB |
| IBAN, Business / VAT ID | IBANs (mod-97 checked), Finnish business IDs (checksum), VAT numbers after a VAT label, IDs from structured data |
| Person name, Organization | From structured data, meta author, RDAP registrant, network owner, document metadata and (low confidence) the AI |
| Cloud storage bucket | S3, Google Cloud Storage, Firebase Storage, Azure Blob, DigitalOcean Spaces, Cloudflare R2, Backblaze, Wasabi, Alibaba OSS |
| Public API key / client ID | Keys that are meant to be public (Google Maps, reCAPTCHA, Stripe publishable, Mapbox, Algolia…) but still identify an account |

**Pivot menus.** Each type has a list of services to check next: for domains ICANN RDAP, crt.sh, urlscan, VirusTotal, Wayback, archive.today, SecurityTrails, BuiltWith relationships, DNSlytics, Shodan, OTX, URLhaus, Netcraft, Robtex, Safe Browsing and a `site:` search; for IPs Shodan, Censys, AbuseIPDB, VirusTotal, GreyNoise, ipinfo, BGP, ViewDNS reverse IP, Spur; for emails search engines, GitHub commits, Gravatar, Have I Been Pwned, Intelligence X; for handles WhatsMyName, GitHub, Keybase; for wallets mempool.space, Blockchair, WalletExplorer, Etherscan, Blockscan, DeBank, Tronscan, Solscan, Cardanoscan and Chainabuse; for coordinates Google Maps, OSM, Google Earth, Bing, Mapillary, SunCalc; for tracker IDs PublicWWW, GitHub code search, DNSlytics reverse analytics/AdSense, SpyOnWeb; for favicons Shodan, FOFA, ZoomEye; for CVEs NVD, CVE.org, Shodan CVEDB, CISA KEV; for organisations OpenCorporates, Wikipedia, LinkedIn; for buckets GrayhatWarfare. The menu also offers *Copy*, *Send to an MCP tool* and *Ask the AI*.

**Security notes**

- Nothing is sent to a pivot service until you click its link. When you do, the value is in the URL you open, so that service learns what you're investigating. See [section 21](#21-operational-security-for-investigators).
- The *Save to Wayback* pivot is marked *(public!)*: it asks the Internet Archive to capture the page, which creates a permanent public record and a request to the target from the archive's servers.

---

## 5. Exposures

Secrets, credentials and personal data that shouldn't be on a public page. Values are **masked** until you tick *Show full values*. Tick a finding to highlight it on the page; *Go to ›* steps through every place it appears.

**Detectors** (41): private keys (PEM and PGP), AWS access keys and secret keys, Google Cloud service-account keys, Azure storage connection strings and SAS tokens, GitHub and GitLab tokens, Slack tokens and webhooks, Discord and Microsoft Teams webhooks, Telegram bot tokens, Stripe live and test keys, OpenAI, Anthropic and generic `sk-` keys, Google OAuth client secrets, Twilio, SendGrid, Mailgun, Mailchimp, npm, PyPI, Shopify, Square, Hugging Face, DigitalOcean, Heroku and Datadog keys, database URLs with passwords, passwords in URLs, hard-coded passwords, JWTs (decoded to show issuer, subject, email and expiry), bearer tokens, IBANs, Finnish personal identity codes, US Social Security numbers and payment cards.

They run over the visible text, the HTML source, HTML comments, inline and same-site scripts, runtime configuration objects, link URLs, resource URLs, hidden form fields and (if enabled) typed form values. Credentials in link URLs (`?token=…`, `?api_key=…`, signed URLs) and secret-looking hidden fields are reported too.

**How false positives are kept down**

- Checksums: cards (Luhn), IBANs (mod-97), Finnish IDs (check character), SSNs (never-issued ranges).
- Entropy thresholds for keys, so `AKIAIOSFODNN7EXAMPLE`-style documentation samples still match but `password = "password"` doesn't.
- Placeholder rejection: `********`, `changeme`, `${SECRET}`, `{{ token }}`, `<your key>` and similar are skipped.
- Specific patterns run before loose ones, so an IBAN isn't also reported as a card number.

**Security notes**

- Exposure values are the most sensitive thing in a report. The Markdown export masks them; the JSON export doesn't. Treat JSON exports as confidential.
- When the AI runs on a remote provider, these values are masked in what's sent. On a local model they're sent in full so the model can judge them.
- A match is a lead. A `sk_test_` key is harmless by design; an `AKIA…` key in a public script usually isn't. Verify before reporting to a site owner, and report responsibly (the site's `security.txt`, shown under Infrastructure, often says how).

---

## 6. Infrastructure

| Section | What it tells you |
|---|---|
| **Security headers** (grade A–F) | HSTS, Content-Security-Policy (with weak-point analysis: `unsafe-inline`, `unsafe-eval`, wildcards, missing `object-src`/`frame-ancestors`), clickjacking protection, `X-Content-Type-Options`, referrer and permissions policies, COOP, CORS. Below it: headers that **leak** software versions, backend names, private IPs or internal hostnames, and every host the CSP allows (a map of the services the site uses, including ones not on this page). |
| **All response headers** | The raw headers of the page. |
| **DNS** | A, AAAA, CNAME, NS, MX, TXT, CAA, SOA for the host and apex. |
| **Email security** | Mail providers inferred from MX and SPF, the SPF record and its `include` domains (each names a service the company uses), DMARC policy and report addresses, MTA-STS, BIMI, and findings such as *SPF ends in +all* or *no DMARC*. |
| **Domain registration (RDAP)** | Creation, update and expiry dates, age in days, registrar and IANA ID, status codes, name servers, DNSSEC, registrant (when the registry publishes it), abuse contact. |
| **IP addresses** | For each resolved IP: network (AS number, name, prefix, country), hosting provider, owner from RDAP, abuse contact, reverse DNS, open ports, detected software and known CVEs (Shodan InternetDB), other hostnames on the IP. Cloudflare and similar are called out because the real origin is then hidden. |
| **Subdomains from certificate transparency** | Every name in public TLS certificate logs for the domain, with notable ones highlighted (dev, staging, vpn, admin, jenkins, mail…), issuers, wildcard use, first and latest certificate. Filterable. |
| **Archive history** | First and last Wayback capture, archived URL count, common file types, archived documents and data files with direct links to the archived copies. |
| **Previous public scans** | urlscan.io results: dates, URLs, IPs, ASNs, servers, titles, screenshots. Useful to see whether others already flagged the site, and what it looked like before. |
| **Google Tag Manager containers** | Every tag ID configured inside the site's GTM containers, which often include analytics and ad accounts not visible in the page source. |
| **The site's public files** | `robots.txt` with interesting disallowed paths, `sitemap.xml` statistics, `security.txt` (and whether it has expired), `humans.txt`, `ads.txt`/`app-ads.txt` with the owner's direct seller accounts, the web-app manifest with related store apps. |
| **Favicon fingerprint** | The icon, its MurmurHash3, MD5 and SHA-256, ready-made Shodan/FOFA/ZoomEye queries. |

Most of this section fills in after **Online lookups** (section 11). Headers, public files and the favicon come from the scan itself.

**Good to know**

- A `robots.txt` entry is a statement that a path exists and that the owner would rather you didn't look. The tool lists it; it doesn't visit it.
- Certificate transparency is retrospective: names appear when a certificate is issued and stay in the logs for ever. A `staging.` name may be long gone.
- `security.txt` is the right channel for reporting an exposure you found.

---

## 7. Tech & trackers

**Tracking, advertising & account IDs.** The strongest pivot in website OSINT. Account IDs belong to the owner, not the site, so the same ID on two sites is strong evidence of a common operator. 72 ID formats are recognised, from Google Analytics (GA4 and legacy UA), Tag Manager, Google Ads, Floodlight, AdSense, AdMob, Meta Pixel and App ID, TikTok, LinkedIn, X, Pinterest, Snap, Reddit and Microsoft pixels, Criteo, Taboola, Outbrain, Amazon Associates, to product analytics and session replay (Hotjar, Clarity, Yandex Metrica, Matomo, Plausible, Segment, Mixpanel, Amplitude, Heap, PostHog, FullStory, Cloudflare), monitoring (Sentry DSN and organisation, New Relic, Bugsnag, Datadog), chat and CRM (Intercom, HubSpot, Drift, Crisp, Tawk.to, Zendesk, Freshworks, LiveChat, Tidio, JivoChat, OneSignal, Mailchimp, Klaviyo), commerce and payments (Shopify store, Stripe, PayPal, Braintree), maps and search (Mapbox, Algolia), captchas and consent tools (reCAPTCHA, hCaptcha, Turnstile, Cookiebot, OneTrust), identity and backend tenants (Auth0, Okta, Cognito, Firebase, Supabase, AppSync, API Gateway).

IDs are pulled from the HTML, the site's script files, resource URLs, the page's runtime state (what the tag manager actually loaded), and the contents of GTM containers. IDs marked **links sites** identify an account; the pivot menu takes you to reverse-lookup services.

**Technologies.** 143 fingerprints across CMSs, site builders, e-commerce platforms, JavaScript frameworks and libraries, UI frameworks, static-site generators, headless CMSs, languages, web frameworks, servers, proxies, caches, CDNs, WAFs, hosting providers and SaaS widgets. Versions come from script URLs, generator tags, headers and the runtime probe. A short, conservative table flags clearly outdated versions of jQuery, jQuery UI, Bootstrap, AngularJS, Lodash, Moment.js, Underscore, Handlebars, Next.js, Nginx, Apache, PHP, IIS, WordPress and Drupal with the related CVEs, and warns about polyfill.io (taken over in 2024).

**Third-party hosts.** Every other site the page loads from or links to, grouped by category (analytics, ads, session replay, CDN, cloud, payments, social, support, consent…) with the service name where known. *Loaded* means your browser contacted it when the page opened.

**Cookies & browser storage.** Names only. Session cookies readable by JavaScript are noted because they'd be exposed to cross-site scripting.

**JavaScript runtime.** Libraries and versions detected from the page's globals, IDs loaded at runtime, and which config objects exist (`__NEXT_DATA__`, `firebaseConfig`…).

**What the site's JavaScript reveals.** API endpoints and paths, cloud storage buckets, internal hostnames (`.internal`, `.corp`, `.local`…), pre-production services (`dev.`, `staging.`, `jenkins.`, `grafana.`…), source maps (which can expose the original source code), build-time environment variables (`NEXT_PUBLIC_*`, `REACT_APP_*`, `VITE_*`…), WebSocket endpoints and developer comments.

**Security notes**

- An exposed *source map* means the un-minified source, often with comments and internal URLs, is downloadable. A *bucket* name is a lead, not a finding, until you check whether it's publicly listable (GrayhatWarfare in the pivot menu indexes those that are).
- Outdated-version warnings depend on the version being visible. Absence of a warning says nothing about safety.

---

## 8. Links & forms

**Forms.** Each form (and inputs outside any form, common on JavaScript-driven login pages): method, where it submits, whether it asks for a password, card or email, field names and types, hidden fields. Forms that send passwords or cards **to another site** or **over plain HTTP** are flagged in red.

**Links.** Every link, de-duplicated, with filters: *worth checking* (documents, data files, configs, archives, executables and links carrying credentials), *all*, *external*, *secret in URL*, *plain HTTP*, *mailto*, *tel*, and by file extension. The ⌖ button scrolls the page to the link.

**Embedded frames and objects**, **script files** (with same/other site and Subresource Integrity status), **HTML comments** (flagged when they mention passwords, TODOs, internal hosts, staging, admin…) and **social sharing tags**.

**Good to know:** a `mailto:` link's address and a `tel:` link's number become indicators even when the visible text says something else.

---

## 9. Files (metadata)

Photos and documents carry metadata that identifies people, devices and places. This tab lists the page's images and linked documents; select some (or *Select documents* / *Select 40 largest images*), press **Analyse selected**, or paste any file URL. Files are downloaded by the extension and parsed locally.

| File type | What's extracted |
|---|---|
| JPEG, PNG, WebP, TIFF | EXIF: camera make and model, lens, software, dates, **GPS position and altitude**, **body and lens serial numbers**, **owner and artist names**, copyright, user comments, Windows XP* tags. XMP: creator, rights, **document and instance IDs** (which link edited copies to the original), creator tool, **edit history**, location fields. IPTC: by-line, credit, city, country, caption, contact. PNG text chunks. |
| PDF | Title, author, subject, keywords, creator and producer (software and version), creation and modification dates, company, XMP; flags for JavaScript, Launch actions and embedded files |
| DOCX, XLSX, PPTX | Creator, last modified by, created/modified/printed dates, revision count, application and version, company, manager, **template path**, total editing time, custom properties, **authors of tracked changes and comments**, co-authoring names, the path the file was saved from, hidden sheets, macros |
| ODT, ODS, ODP | Initial creator, creator, dates, generator, editing cycles and duration, printed by |
| Legacy .doc/.xls/.ppt | File paths found in the binary |

Any file path (`C:\Users\jsmith\…`, `\\fileserver\share\…`, `/Users/name/…`) is mined for **user names** and server names. Identifying rows are highlighted. GPS positions get map links. Authors, user names, companies and coordinates become indicators, and every file's SHA-256 is recorded.

**Security notes**

- Downloading a file is a normal request to the file's server. For files on other sites the extension needs access to that site (it asks).
- Files are parsed, never opened or executed. PDF warnings (*Contains JavaScript*, *Launch action*) are reasons to be careful if you open the file yourself.
- Metadata can be wrong or planted. Camera clocks drift, and GPS tags can be edited. Treat it as evidence to corroborate.

---

## 10. Phishing and scam triage

The score (0–100) and level (*minimal*, *low*, *medium*, *high*) on the summary card come from explained, weighted signals. The score is a triage aid, not a verdict: a legitimate start-up can trip *new domain*, and a phishing kit on a hacked old site won't. Read the signals.

| Group | Signals (weight) |
|---|---|
| The URL | bare IP host (20), credentials over plain HTTP (25), punycode domain (12; 30 if it mixes scripts, e.g. Latin and Cyrillic), free hosting or tunnelling service (10), abused top-level domain (6), deep subdomain (8), many hyphens (6), very long host (5), `@` in URL (15), login/verify/secure keyword in a subdomain (8) |
| Brand impersonation | brand name in a domain it doesn't own (25), misspelling of a brand (25), page title claims a brand while asking for credentials elsewhere (20), favicon loaded from the brand's servers (18), brand images/styles loaded from the brand (10). 76 frequently impersonated brands with the domains they really use: payment, banks, mail, cloud, logistics, crypto, gaming, government. |
| Forms | password/card form submits to another site (20), to Telegram, Discord, Formspree, webhook or tunnelling services (30), `data:`/`javascript:` action (15), generic PHP handler (8), no password-recovery link (4), asks for both password and card (10) |
| Content | urgency and threat language in several languages (up to 15), seed-phrase request (35), most links point off-site (10), many dead `#` links (4) |
| Behaviour | right-click blocked (5), developer-tools detection (8), obfuscated JavaScript (10), meta refresh (5), full-page iframe of another site (12), `noindex` on a login page (4), wallet-connect with airdrop/claim lure (25), ClickFix: asks you to paste a command into Run or a terminal (35) |
| Registration | domain under 30 days old (25), under 6 months (10). Needs online lookups. |

Without a sensitive form (password, card, seed phrase) or a drainer/ClickFix/exfiltration pattern, the total is halved, because most phishing needs you to type something.

**Good to know**

- The **Phishing triage** AI mode reads these signals plus the page text and explains what's decisive.
- Lookalike detection decodes punycode and maps confusable characters to ASCII before comparing, so `pаypal.com` with a Cyrillic *а* is caught.
- To report: the brand's abuse address, Google Safe Browsing (in the domain pivots), URLhaus, and the hosting provider's abuse contact (shown under IP addresses).

---

## 11. Online lookups

Pressing **Online lookups** (or enabling auto-run) queries public services about the domain and its IPs. The target site is not contacted. No API keys are needed; a urlscan.io key is optional for higher limits.

| Source | Service contacted | Result |
|---|---|---|
| DNS records | Cloudflare DNS over HTTPS, Google as fallback | A, AAAA, CNAME, NS, MX, TXT, CAA, SOA, DMARC, MTA-STS, BIMI, reverse DNS |
| Domain & IP registration | IANA bootstrap, the domain's registry RDAP server, rdap.org, ARIN (redirects to the right regional registry) | Registrar, dates, age, status, registrant, network owner, abuse contacts |
| ASN / hosting | Team Cymru, via DNS | AS number and name, prefix, country, hosting provider |
| Open ports & CVEs | Shodan InternetDB | Ports, software, vulnerabilities, tags (refreshed weekly) |
| Subdomains | crt.sh, Cert Spotter as fallback | Names from certificate transparency logs |
| Archive history | Wayback Machine CDX API | Capture dates, URL counts, archived documents |
| Previous scans | urlscan.io | Public scans of the domain |
| Tag Manager containers | googletagmanager.com | Tag IDs inside the site's containers |

Lookups typically take 10–60 seconds; crt.sh and the Wayback Machine are the slow ones. Each source can be disabled in Settings → Online lookups. Results merge into the report as indicators (IPs, name servers, mail servers, subdomains, verification tokens from TXT records, SPF include domains, DMARC addresses, ASNs, network owners, CVEs) and the phishing score is updated with the domain age.

**Security notes**

- Each service learns the domain (and IPs) you looked up. See section 21.
- InternetDB data can be weeks old; a listed CVE means Shodan saw a vulnerable banner at some point, not that the host is exploitable now.
- The AI's built-in tools use the same sources and the same on/off switches.

---

## 12. AI analysis

The model receives a digest of everything the scan found (plus online results, file metadata, MCP results and correlations when present) and the visible page text, and returns a structured brief: **verdict**, **risk level**, **summary**, **attribution** (who runs the site and the evidence), **key findings** with severity and evidence, **entities**, **exposures** with recommendations and **suggested pivots**. You can then ask follow-up questions in a conversation that keeps the context.

**Modes**

| Mode | Focus |
|---|---|
| OSINT brief | What the site is, who runs it, how it connects to other sites, people and organisations, what's exposed, best next pivots |
| Phishing / scam triage | Phishing, scam, fake shop, drainer, malware or legitimate, with decisive evidence and reporting steps |
| Data exposure audit | Personal data, credentials, confidential material, leaky metadata and misconfigurations, with fixes; confirms or dismisses the regex findings |
| Custom question | Anything, with the same data |

**Providers**

| Provider | Where data goes | Notes |
|---|---|---|
| **Ollama** (default) | Your computer | Use a model with tool support. `qwen3:8b` works well. *Thinking* is on by default: it makes small models far better at deciding to call tools. |
| **OpenAI-compatible** | Wherever the URL points | LM Studio, llama.cpp, vLLM, LocalAI, Jan locally; OpenRouter, OpenAI and others remotely |
| **Anthropic** | Anthropic's API | Your own key, used directly from the browser |

**Tools.** With *Let the AI use tools* on, the model can call built-in lookups (DNS, RDAP for domains and IPs, ASN, open ports, certificate transparency, archive history, urlscan), read any report section, search the page text, and call the tools of every MCP server you've marked *Offer this server's tools to the AI*. Built-in tools are limited to sources you've enabled. The panel shows each call live with its arguments and result. The number of calls per analysis is capped (default 12).

**Security notes**

- **Prompt injection is real.** A hostile page can contain text written to manipulate a model: "ignore your instructions and…". OSINT Lens wraps page content and every tool result as untrusted data and instructs the model never to follow instructions inside them, and tells it to report such attempts as a finding. No model is immune, which is why the next two points exist.
- **MCP tool calls need your approval** unless you've relaxed the policy for that server. The prompt shows the server, the tool, whether it's marked read-only, and the exact arguments. Check that the arguments are things you'd send yourself.
- **Remote providers receive page content.** Secrets found by the exposure detectors are masked before sending. Page text itself is not masked (the model needs it), so for sensitive investigations use a local model.
- Model output is advisory. Entities the AI names are added as low-confidence indicators and labelled *AI analysis*. Findings cite evidence so you can check them.
- Local models with 8k–16k context windows see a truncated digest on big pages. The *Max page characters* and Ollama *Context window* settings control this.

---

## 13. MCP tools

[Model Context Protocol](https://modelcontextprotocol.io) servers give OSINT Lens capabilities it doesn't ship with: threat-intelligence lookups (VirusTotal, Shodan, AbuseIPDB, passive DNS…), search engines and page fetchers, a headless browser, your own database or case-management system.

**Ways to use a connected server**

1. **Run a tool yourself** from the MCP tab. Pick the server and tool; a form is generated from the tool's schema with values from the current page suggested (the URL, host, domain, IPs, emails, tracker IDs…). Results, including images, are kept with the report. Tools you run yourself never need approval.
2. **Recipes**: save a call with placeholders (`{url}`, `{host}`, `{domain}`, `{title}`, `{ip}`, `{email}`) and run it on any page with one click, or automatically after every scan. Good for routine enrichment such as reputation checks.
3. **Let the AI use the tools** during its analysis (per server), subject to the approval policy.
4. **Send an indicator** to a tool from any pivot menu.

**Connecting servers.** Remote servers connect by URL with optional headers (`Authorization: Bearer …`, `X-API-Key: …`). The client speaks all current protocol versions: the stateless 2026-07-28 Streamable HTTP, the 2025 Streamable HTTP with sessions, and the legacy 2024 HTTP+SSE transport, detected automatically. Local servers you run with `npx`, `uvx` or `docker` connect through the bundled bridge (section 23). Settings shows the server's info, protocol, tool list and lets you hide tools.

**Approval policies** (per server)

| Policy | Behaviour |
|---|---|
| Ask every time (default) | Each AI call shows a prompt: *Allow once*, *Always allow this tool*, *Deny*. Unanswered prompts are denied after five minutes. |
| Auto-approve read-only tools | Tools the server marks `readOnlyHint` run without asking. The server supplies that flag, so use this only for servers you trust. |
| Never ask | Trusted servers only |

**Security notes**

- Tool arguments are sent to the server. Never approve a call that would send a secret or personal data you found on the page to a third-party service you don't control.
- A server's tool descriptions and annotations are text the server controls. A malicious server could describe a tool misleadingly; the approval prompt shows what's really being sent.
- Remote servers must use `https://` (the settings page enforces this for non-local hosts). Chrome asks for permission to reach each new server.
- The MCP client doesn't support servers that need to ask *you* questions mid-call (sampling, elicitation); such tools return an explanatory error instead.

---

## 14. Lookup

Paste anything, or select text on a page and right-click → *Investigate*. OSINT Lens recognises what it is (domain, URL, IP, email, phone, wallet, handle, tracker ID, favicon hash…), shows the pivot services for each recognised type, searches your History for the same value, and can hand it to an MCP tool. A warning appears if the value looks like a secret, because pivot links would send it to third parties. The context menu also offers *Investigate this link* and *Check this image's metadata*.

---

## 15. History and correlation

Every scan is saved in your browser's local database (IndexedDB). History lists reports newest first with risk level, counts, tags, notes and AI markers, and searches across URLs, titles, tags **and every indicator value**: type an email, a GA ID or an IP and find every site where it appeared.

**Correlation.** Each report's correlatable indicators are indexed. When a new scan shares one with an earlier report, the Overview lists it under *Seen in your earlier investigations* and the relationship graph draws the link. Third-party service domains (CDNs, analytics hosts) are excluded from the index so that every site isn't linked to every other site through Google.

**Retention.** The newest *N* reports are kept (default 300; configurable). Starred reports are never pruned. With *Keep a history of scans* off, a report is deleted when its tab closes unless starred. You can delete single reports, everything, or export all reports as JSON.

**Security notes**

- Reports contain page text, exposure values and anything the AI or MCP tools returned. Anyone with access to your Chrome profile can read them. Use *Delete all scan history* when an investigation ends, or turn history off for sensitive work.
- History never leaves the browser. Removing the extension deletes it.

---

## 16. Evidence capture

From the summary card, **Evidence ▾** saves either a **screenshot** of the visible area (PNG) or a **full-page archive** (MHTML: the HTML with all its resources in one file). Each capture records the URL, title, time and **SHA-256 hash**, listed in the report and included in exports. Captures are stored locally with the report.

**Good to know:** a hash recorded at capture time lets you show later that the file hasn't changed. For court-grade evidence, also use an independent archive (the Wayback and archive.today pivots) and keep your own notes of what you did and when.

---

## 17. Exports

| Format | Contents | Use |
|---|---|---|
| Markdown report | Summary, AI brief, phishing signals, exposures (masked), all indicators by type, technologies, infrastructure, file metadata, evidence hashes, notes | Reading, sharing, pasting into a case file |
| Full data (JSON) | Everything, unmasked | Archiving, scripting, re-import |
| Indicators (CSV) | One row per indicator with type, value, label, confidence, count, sources | Spreadsheets, other tools. Values starting with `=`, `+`, `-`, `@` are prefixed so they can't run as spreadsheet formulas. |
| STIX 2.1 bundle | Observables (domains, IPs, emails, URLs, ASNs, file hashes), vulnerabilities, identities, a report object and a note with identifiers STIX has no object for (tracker IDs, wallets, phones…) | OpenCTI, MISP and other threat-intelligence platforms |

Settings can also be exported (without API keys and tokens unless you tick the box) and imported.

---

## 18. Settings

**AI analysis**: provider and model (*Load models* lists what's installed and shows a model's capabilities), Ollama context window and thinking, max page characters, timeout, temperature, tool use and call limit, auto-run after scans.

**MCP servers**: add remote servers or a local bridge; name, URL, transport, headers, approval policy, tool visibility, *Offer this server's tools to the AI*; *Test connection*.

**Recipes**: saved MCP calls with placeholders; auto-run toggle.

**Scanning**: read the site's public files; download its scripts (and how many); detect libraries and runtime IDs; fingerprint the favicon; scan typed form values; run online lookups automatically.

**Online lookups**: one switch per source; optional urlscan.io key.

**Privacy & data**: keep history and how many reports; theme; site access (grant or revoke *all sites*); export/import settings; delete all history.

Settings are stored in the extension's local storage, not synced between devices, because they can contain keys and tokens.

---

## 19. Permissions and site access

| Permission | Why it's needed |
|---|---|
| `activeTab` | Read the tab you invoke the extension on by clicking the icon, using the shortcut or a context-menu item. Access lasts until that tab navigates. |
| `tabs` | See tab URLs and titles, so the panel knows which site you're on and can offer *Allow on this site*. Chrome labels this "read your browsing history"; the extension only reads the current tab's URL when you use it. |
| `scripting` | Inject the collector, the runtime probe, the fetcher and the highlighter into the page |
| `storage`, `unlimitedStorage` | Settings, progress state and the local report database |
| `sidePanel`, `contextMenus` | The user interface |
| `pageCapture` | Full-page MHTML evidence |
| Host: `localhost`, `127.0.0.1` | Ollama, local AI servers, the MCP bridge |
| Host: the lookup services and `api.anthropic.com` | Online lookups and the Anthropic provider |
| Optional host: all sites | Requested only when you choose it (per site when prompted, or all sites in Settings). Needed to scan a tab you didn't click the icon on, to download files from other sites, and to reach remote AI or MCP servers (requested per server). |

**Site access, in practice.** Clicking the toolbar icon on a page grants one-time access to that tab. If you then navigate or switch tabs and press *Scan page*, the panel asks: **Allow on this site** (remembered for that site) or **Allow on all sites**. Most people allow all sites once; you can revoke it in Settings at any time.

---

## 20. Security model

What the extension does to protect you, in one place.

- **No backend, no telemetry.** Nothing phones home. Every network request is listed in [PRIVACY.md](PRIVACY.md).
- **Isolation from the page.** Collection runs in Chrome's isolated world. The one main-world probe is read-only and returns plain data. Pages can't message the extension; only its own pages can.
- **Untrusted content is text.** Everything from pages, tool results and models is rendered as text, never as HTML. The extension pages have a strict Content Security Policy that allows only their own scripts. Links are limited to `http(s)`, `mailto` and extension URLs.
- **Requests don't carry your identity.** Fetches made by the extension omit cookies and the referrer.
- **Passive by design.** Only files any visitor requests are fetched. No path guessing, no port scanning, no form submission.
- **AI guard rails.** Untrusted-data framing, approval prompts for MCP calls, masked secrets for remote providers, capped tool calls, evidence-cited findings.
- **MCP guard rails.** HTTPS required for remote servers, per-origin permission prompts, per-server approval policies, tool hiding, a bridge that is local-only, token-protected and rejects web-page origins and DNS-rebinding.
- **Masking by default** in the panel and in Markdown exports.
- **Everything local**: settings, reports, evidence and the indicator index live in your Chrome profile.

Found a weakness? See [SECURITY.md](../SECURITY.md).

---

## 21. Operational security for investigators

Things to consider when the subject of an investigation must not learn about it, or when you handle sensitive material.

- **A scan touches the target** in the same way a visit does: requests for the page, its scripts, favicon and public files, from your IP, without cookies. If even that is too much, you've already loaded the page in your browser; the extra requests look like a browser fetching the same site's assets.
- **Online lookups don't touch the target**, but the lookup services (Cloudflare/Google DNS, registries, crt.sh, Shodan, the Internet Archive, urlscan.io) see which domain you asked about. urlscan.io searches are read-only here; the tool never submits a scan to urlscan.
- **Pivot links** send the value to the service you open. Some services (and some search engines) keep query logs; a few make them public. The *Save to Wayback* pivot creates a public, permanent record and a crawl of the target.
- **AI providers** that aren't on your machine receive the page text. Use Ollama or another local server for sensitive cases.
- **MCP servers** receive what you approve. Know who runs them.
- **Files** you analyse are downloaded from their server, with your IP.
- **Reports are local but unencrypted** inside your Chrome profile. Delete history when done, or turn it off.
- **Your browser's fingerprint, IP and existing logins** are unchanged by the extension. For isolation, use a dedicated browser profile or a VPN as your own policy requires.

---

## 22. Reading the results: confidence and false positives

- **Confidence levels** on indicators: *high* when the format is unambiguous or the value was seen in several places; *medium* for bare domains in text, national phone formats, IDs that need context; *low* for @handles, hash-like strings, placeholder emails and anything the AI named. *Hide low-confidence* is one click.
- **Checksums** make cards, IBANs, personal IDs and most wallet addresses reliable. Keys and tokens are matched by format and entropy: a documented example key matches too.
- **Tracker IDs** are only as meaningful as the service: a GA4 ID shared by two sites is strong evidence; a shared Google Fonts host is nothing.
- **Phishing score** is a weighted sum of hints. Always read which signals fired.
- **Technology versions** come from file names and headers that sites can fake or strip; absence of a warning isn't a clean bill.
- **Online data** has lag: InternetDB (weekly), certificate logs (historical), Wayback (whenever it crawled).
- **AI output** is advisory and can be wrong or manipulated; its findings cite the evidence so you can check them.

When something matters, verify it with a second source before you act on it or report it.

---

## 23. Reference: the MCP bridge

`tools/mcp-bridge.mjs` (Node 18+, no dependencies) runs stdio MCP servers and exposes them over Streamable HTTP for the extension.

```bash
node tools/mcp-bridge.mjs -- npx -y @modelcontextprotocol/server-everything
```

```bash
node tools/mcp-bridge.mjs --config mcp-servers.json --token <your-secret>
```

| Option | Meaning |
|---|---|
| `-- <command…>` | One server; served at `/mcp` |
| `--config <file>` | Several servers from a Claude Desktop-style `mcpServers` file; each at `/<name>/mcp` |
| `--port`, `--host` | Default `8765` on `127.0.0.1` |
| `--token` | Fixed bearer token (otherwise a random one is printed at start) |
| `--allow-origin` | Restrict to a specific `chrome-extension://<id>` |
| `--timeout` | Seconds per request (default 120) |
| `--no-auth` | Disable the token; for throwaway testing only |

It initialises each child process once and shares it between reconnects, answers server-to-client `ping` and `roots/list` itself, requires the bearer token, rejects web-page origins and non-localhost `Host` headers, and `GET /` lists the servers. Full details in [MCP.md](MCP.md).
