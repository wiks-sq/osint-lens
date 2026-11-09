# Contributing

Thanks for helping. Bug reports, detection rules, pivot services and fixes are all welcome.

## Setup

```bash
git clone <this repo> && cd osint-lens
npm install          # only installs puppeteer-core for the browser test
npm test             # unit tests
npm run check        # static checks
npm run test:e2e     # optional: needs Chrome or Chromium (CHROME_PATH)
```

Load the folder with **Load unpacked** on `chrome://extensions` and press reload on the extension's card after each change.

## Guidelines

- **No runtime dependencies and no build step.** Chrome loads `src/` as plain ES modules. Keep it that way.
- **Keep `src/core` pure** (no `chrome.*`, no network) so it stays unit-testable in Node.
- **Every new rule needs a test**: detectors, tracker IDs, fingerprints, pivots, phishing signals. Include a positive case and, where false positives are likely, a negative one.
- **Injected functions must be self-contained.** Functions in `src/content/` are serialised by Chrome, so they can't reference imports or outer variables.
- **Never insert page or model content as HTML.** Use the `h()` helper in `src/ui/dom.js`.
- **Privacy first.** New network calls must be opt-in or clearly user-initiated, listed in `docs/PRIVACY.md`, and their hosts added to `manifest.json`.
- Code style: 2-space indent, double quotes, semicolons, descriptive names, comments that explain *why*.

## Pull requests

Describe what changed and why, link any issue, and make sure `npm test` and `npm run check` pass. For UI changes, add a screenshot.
