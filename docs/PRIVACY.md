# Privacy and data flows

OSINT Lens has no server, no account and no telemetry. This page lists every place data goes.

## What is read from the page

| Data | Read? | Stored? |
|---|---|---|
| Visible text, HTML, links, scripts, meta tags, comments | Yes | In the local report (text capped at 300 KB) |
| Network requests the page made (URLs from the Performance API) | Yes | Third-party host summary only |
| Cookie and localStorage/sessionStorage **names** | Yes | Yes |
| Cookie and storage **values** | **Never** | — |
| Password field values | **Never** (only "is filled in") | — |
| Other form field values | Only if you enable *Scan values typed into form fields* | Only what the detectors flag |
| JavaScript globals (framework versions, tag-manager IDs, config objects) | Yes, read-only, if the runtime probe is on | Versions and IDs |

## Network requests the extension makes

| When | To | What is sent |
|---|---|---|
| Every scan (can be turned off in Settings → Scanning) | The scanned site | Requests for the page itself (to read headers), `robots.txt`, `security.txt`, `humans.txt`, `ads.txt`, `app-ads.txt`, `sitemap.xml`, the manifest, its script files and its favicon, as a normal visitor's browser would |
| You press **Online lookups** (or enable auto-run) | `cloudflare-dns.com` / `dns.google`, `data.iana.org`, the domain's RDAP registry / `rdap.org` / `rdap.arin.net`, `crt.sh` / `api.certspotter.com`, `web.archive.org`, `internetdb.shodan.io`, `urlscan.io`, `www.googletagmanager.com` | The domain, host, its IP addresses and GTM container IDs. Each source can be disabled. |
| You analyse **files** | The file's own server | A normal download of that file |
| You click a **pivot link** | That service, in a new tab | The value in the link (nothing is sent until you click) |
| **AI** with Ollama or another local server | `localhost` | The digest and page text. They stay on your computer. |
| **AI** with a remote provider (OpenAI-compatible remote URL, Anthropic) | That provider | The digest and page text, **with secrets masked** |
| **AI tool calls** (built-in) | The same public sources as online lookups | The arguments the model chose |
| **MCP tools** | The MCP server you configured | The tool arguments you entered or approved |

The extension never sends cookies or credentials of the page to anyone. Lookups are made with `credentials: "omit"` and no referrer.

## Where data is stored

Everything stays in your Chrome profile:

- **Settings** (including API keys and MCP headers) in `chrome.storage.local`. They are not synced to other devices. Export them without secrets by default.
- **Reports, the indicator index and evidence** in the extension's IndexedDB. Delete single reports in History or everything in Settings → Privacy & data. History is pruned to the limit you set; starred reports are kept.
- **Progress state** in `chrome.storage.session`, which is memory only and cleared when the browser closes.

Removing the extension deletes all of it.

## Masking

Values found by the exposure detectors are masked in the UI until you tick *Show full values*. They are masked in the AI digest whenever the AI endpoint isn't on your computer. Markdown exports mask exposure values. JSON exports contain everything; treat them as sensitive.

## Recommendations

- Prefer Ollama or another local model for sensitive investigations.
- Disable online sources you don't need. Every lookup tells that service which domain you are interested in.
- Keep MCP approval on *Ask every time* for servers you don't fully trust.
- Remember that pivot links send the value to the service you open.
