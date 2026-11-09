// Settings: defaults, loading (deep-merged over defaults) and saving.
// Stored in chrome.storage.local, not sync: they can contain API keys and MCP
// tokens that shouldn't be copied to other devices.

export const DEFAULTS = {
  scan: {
    includeFormValues: false, // scan values typed into form fields (password values are never read)
    wellKnown: true, // read robots.txt, security.txt, sitemap.xml, ads.txt, humans.txt, manifest from the site
    externalScripts: true, // download the site's own scripts to look for IDs, endpoints and secrets
    maxScripts: 40,
    mainWorldProbe: true, // detect framework versions and runtime tracker IDs from page JavaScript
    favicon: true,
    autoOnline: false // run online lookups automatically after every scan
  },
  online: {
    dns: true,
    rdap: true,
    asn: true,
    internetdb: true,
    ct: true,
    wayback: true,
    urlscan: true,
    gtm: true,
    urlscanKey: ""
  },
  ai: {
    provider: "ollama", // "ollama" | "openai" | "anthropic"
    ollama: { url: "http://localhost:11434", model: "", numCtx: 16384, think: true }, // thinking makes small models far better at tool calling
    openai: { url: "http://localhost:1234/v1", apiKey: "", model: "" },
    anthropic: { apiKey: "", model: "claude-sonnet-5-5" },
    maxChars: 24000,
    timeoutSec: 300,
    temperature: 0.2,
    useTools: true, // let the model call built-in lookups and MCP tools
    maxToolCalls: 12,
    autoRun: false
  },
  mcp: {
    servers: [] // { id, name, url, transport, headers: [{name, value}], enabled, useInAi, approval, disabledTools: [] }
  },
  recipes: [], // { id, name, serverId, tool, args, auto }
  privacy: {
    keepHistory: true,
    historyLimit: 300,
    maskValues: true
  },
  ui: { theme: "system" }
};

const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);

export function deepMerge(base, over) {
  if (!isObj(base) || !isObj(over)) return over === undefined ? structuredClone(base) : over;
  const out = structuredClone(base);
  for (const [k, v] of Object.entries(over)) out[k] = isObj(base[k]) && isObj(v) ? deepMerge(base[k], v) : v;
  return out;
}

export async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return deepMerge(DEFAULTS, settings || {});
}

export async function saveSettings(settings) {
  await chrome.storage.local.set({ settings: deepMerge(DEFAULTS, settings) });
}

/** Partial update: patch is merged over the current settings. */
export async function updateSettings(patch) {
  const cur = await getSettings();
  const next = deepMerge(cur, patch);
  await chrome.storage.local.set({ settings: next });
  return next;
}

/** Short random id. */
export const newId = () => crypto.getRandomValues(new Uint32Array(2)).reduce((s, n) => s + n.toString(36), "");
