# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's **Report a vulnerability** button (Security → Advisories) rather than in a public issue. Include steps to reproduce and the impact. You should get a response within a week.

## Scope

Particularly interesting:

- a scanned web page that can run script in, or inject HTML into, the extension's pages;
- a scanned page or a model answer that can make the extension send data somewhere without the user's action or approval (for example, bypassing MCP tool approvals);
- the MCP bridge accepting requests from web pages or remote hosts, or without the token;
- secrets being sent to a remote AI provider unmasked, or leaking into exports where they shouldn't.

Detection gaps and false positives are not security vulnerabilities. Please open a normal issue for those.

## Design notes

- Extension pages use a strict CSP (`script-src 'self'`). All untrusted content is inserted as text.
- Collection runs in Chrome's isolated world. The only main-world code is a small read-only probe.
- Only the extension's own pages can send messages to the service worker.
- MCP tool calls by the AI require approval unless the user relaxes the policy for a server.
