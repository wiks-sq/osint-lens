#!/usr/bin/env node
// Static checks that catch the mistakes that break an unpacked extension:
// files referenced by the manifest or by HTML pages are missing, an import
// points at a file that doesn't exist, or a module has a syntax error.
// Usage: node scripts/check.mjs

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];
const err = (m) => errors.push(m);

const walk = (dir) => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  return statSync(p).isDirectory() ? walk(p) : [p];
});

// 1. Manifest
const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
const refs = [
  manifest.background?.service_worker,
  manifest.side_panel?.default_path,
  manifest.options_page,
  ...Object.values(manifest.icons || {}),
  ...Object.values(manifest.action?.default_icon || {})
].filter(Boolean);
for (const r of refs) if (!existsSync(join(root, r))) err(`manifest.json references missing file: ${r}`);
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
if (pkg.version !== manifest.version) err(`Version mismatch: package.json ${pkg.version} vs manifest.json ${manifest.version}`);

// 2. HTML pages: scripts and stylesheets they load
const files = walk(join(root, "src"));
for (const f of files.filter((f) => f.endsWith(".html"))) {
  const html = readFileSync(f, "utf8");
  for (const m of html.matchAll(/(?:src|href)="([^"#:]+\.(?:js|css|png|html))"/g)) {
    if (!existsSync(resolve(dirname(f), m[1]))) err(`${relative(root, f)} references missing ${m[1]}`);
  }
  if (/<script(?![^>]*\bsrc=)[^>]*>[^<]+<\/script>/i.test(html)) err(`${relative(root, f)} has an inline script (blocked by the extension CSP)`);
}

// 3. JS modules: syntax and relative imports
const js = [...files, ...walk(join(root, "tools")), ...walk(join(root, "scripts"))].filter((f) => /\.(m?js)$/.test(f));
for (const f of js) {
  try {
    execFileSync(process.execPath, ["--check", f], { stdio: "pipe" });
  } catch (e) {
    err(`Syntax error in ${relative(root, f)}:\n${String(e.stderr || e.message).trim()}`);
  }
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(/^\s*(?:import|export)\s[^"']*?from\s+["'](\.{1,2}\/[^"']+)["']/gm)) {
    if (!existsSync(resolve(dirname(f), m[1]))) err(`${relative(root, f)} imports missing ${m[1]}`);
  }
  for (const m of src.matchAll(/import\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g)) {
    if (!existsSync(resolve(dirname(f), m[1]))) err(`${relative(root, f)} dynamically imports missing ${m[1]}`);
  }
  // Extension pages and the service worker can't use Node built-ins.
  if (f.includes(`${join(root, "src")}`) && /from\s+["']node:/.test(src)) err(`${relative(root, f)} imports a Node built-in`);
}

// 4. Named imports exist in the target module (cheap static check)
const exportsOf = new Map();
const exportNames = (file) => {
  if (exportsOf.has(file)) return exportsOf.get(file);
  const src = readFileSync(file, "utf8");
  const names = new Set();
  for (const m of src.matchAll(/^export\s+(?:async\s+)?(?:function\*?|class|const|let|var)\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[1]);
  for (const m of src.matchAll(/^export\s*\{([^}]+)\}/gm)) for (const part of m[1].split(",")) names.add(part.trim().split(/\s+as\s+/).pop());
  exportsOf.set(file, names);
  return names;
};
for (const f of js.filter((f) => f.startsWith(join(root, "src")))) {
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(/^import\s*\{([^}]+)\}\s*from\s*["'](\.{1,2}\/[^"']+)["']/gm)) {
    const target = resolve(dirname(f), m[2]);
    if (!existsSync(target)) continue;
    const have = exportNames(target);
    for (const part of m[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0].trim();
      if (name && !have.has(name)) err(`${relative(root, f)} imports "${name}" which ${relative(root, target)} doesn't export`);
    }
  }
}

if (errors.length) {
  console.error(`✗ ${errors.length} problem(s):\n`);
  for (const e of errors) console.error(`- ${e}`);
  process.exit(1);
}
console.log(`✓ ${js.length} modules, ${refs.length} manifest references and ${files.filter((f) => f.endsWith(".html")).length} pages checked`);
