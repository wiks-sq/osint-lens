# Using MCP servers with OSINT Lens

The [Model Context Protocol](https://modelcontextprotocol.io) lets OSINT Lens use tools from any MCP server: threat-intelligence APIs, search, a headless browser, your own database or case-management system. You can run tools yourself, save them as recipes, or let the AI call them during an analysis.

## Adding a remote (HTTP) server

1. **Settings → MCP servers → Add server.**
2. Give it a short **name** (letters, digits, `- _ .`). Tool names shown to the AI are prefixed with it.
3. Enter the **URL** of the MCP endpoint, e.g. `https://mcp.example.com/mcp`. Servers that aren't on your computer must use `https://`.
4. Add **headers** if the server needs authentication, e.g. `Authorization: Bearer <token>` or `X-API-Key: <key>`.
5. Pick a **tool approval** policy (below) and press **Test connection**. Chrome asks for permission to reach that server once.
6. Untick any tools you don't want the AI or the MCP tab to use, then **Save**.

### Transports

| Setting | Protocol | Notes |
|---|---|---|
| Auto-detect (default) | tries the three below in order | The result is shown after *Test connection* |
| Streamable HTTP (2026-07-28) | stateless: every request carries its version and client info in `_meta`, plus `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers; discovery via `server/discover` | No sessions, no handshake |
| Streamable HTTP (2025) | `initialize` handshake, `Mcp-Session-Id`, `MCP-Protocol-Version` | Negotiates 2025-11-25, 2025-06-18 or 2025-03-26. Re-initialises when a session expires. |
| HTTP + SSE (2024-11-05) | GET event stream with an `endpoint` event, then POST messages | For older servers |

Responses can be plain JSON or an SSE stream. Progress notifications are read, and server pings are answered. Server-initiated sampling, elicitation and roots aren't supported; a tool that needs them returns an explanatory error.

### Approval policies

| Policy | Behaviour |
|---|---|
| **Ask every time** (default) | Every AI tool call shows the arguments and waits for *Allow once*, *Always allow this tool* or *Deny* (5-minute timeout, then denied) |
| **Auto-approve read-only tools** | Tools the server marks `readOnlyHint: true` run without asking. Annotations come from the server, so only use this for servers you trust. |
| **Never ask** | For servers you fully trust |

Tools you run yourself from the MCP tab never need approval, because you are the one running them.

**Why approvals matter.** The AI reads untrusted web pages. A malicious page can contain text designed to make a model misuse tools, for example by sending data to an attacker-controlled address. OSINT Lens marks page content and tool results as untrusted and the prompt forbids following embedded instructions, but no model is immune. The approval prompt is your last check.

## Local (stdio) servers through the bridge

Most MCP servers are programs you start with `npx`, `uvx` or `docker` and talk to over stdin/stdout. A browser extension can't start programs, so OSINT Lens includes a bridge (`tools/mcp-bridge.mjs`, Node 18+, no dependencies) that runs them and exposes them over HTTP.

**One server:**

```bash
node tools/mcp-bridge.mjs -- npx -y @modelcontextprotocol/server-everything
```

Add it in Settings with **Add local bridge**: URL `http://127.0.0.1:8765/mcp` and header `Authorization: Bearer <token printed by the bridge>`.

**Several servers:** copy `mcp-servers.example.json` to `mcp-servers.json`. The format is the same as Claude Desktop's `mcpServers` config, so you can reuse that file. Then run:

```bash
node tools/mcp-bridge.mjs --config mcp-servers.json --token my-long-random-secret
```

Each server is served at `http://127.0.0.1:8765/<name>/mcp`. Add one entry per server in Settings. `GET http://127.0.0.1:8765/` lists them.

**Options:** `--port`, `--host` (keep it local), `--token` (fixed token across restarts), `--allow-origin chrome-extension://<id>` (restrict to your extension's ID), `--timeout <seconds>`, `--no-auth` (testing only).

**Security model**

- It listens on `127.0.0.1` only, unless you choose otherwise.
- Every request needs the bearer token.
- Requests with a web-page `Origin` are rejected. Only extension origins and non-browser clients are allowed.
- Requests whose `Host` header isn't localhost are rejected, which protects against DNS rebinding.
- Each child process is initialised once and shared by later connections, so a service-worker restart doesn't re-initialise your server. Server-to-client requests are answered by the bridge: `ping` → `{}`, `roots/list` → no roots, anything else → *method not found*.

## Recipes

A recipe is a saved tool call whose arguments can contain placeholders that are filled from the current report:

| Placeholder | Value |
|---|---|
| `{url}` | page URL |
| `{host}` | hostname |
| `{domain}` | registrable domain |
| `{title}` | page title |
| `{ip}` | first public IP found (run online lookups first for resolved addresses) |
| `{email}` | first email found |

Create one from the MCP tab with **Save as recipe**: values from the current page are turned into placeholders automatically. You can also create and edit recipes in Settings. Tick *Run automatically after every scan* to run a recipe on every scan; this suits enrichment such as reputation lookups.

## Ideas for servers

- Threat intelligence: reputation and passive DNS for domains, IPs and hashes
- Search engines and web fetchers, to read pages linked from the target
- A headless-browser server, to follow redirect chains safely
- Your notes or case system, to file findings straight from the panel
- A SQL or graph database, to correlate with your own data

Check each server's documentation for how to run it and what it needs. Many need API keys, which you pass in the bridge config's `env` or in HTTP headers.
