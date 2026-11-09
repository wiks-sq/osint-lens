#!/usr/bin/env node
// Builds dist/osint-lens-<version>.zip: the files Chrome needs, ready for
// "Load unpacked" (after unzipping) or for the Chrome Web Store. No dependencies.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join, relative, dirname, resolve } from "node:path";
import { deflateRawSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
execFileSync(process.execPath, [join(root, "scripts/check.mjs")], { stdio: "inherit" });
const { version } = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
const INCLUDE = ["manifest.json", "LICENSE", "README.md", "src", "icons"];

const walk = (p) => (statSync(p).isDirectory() ? readdirSync(p).sort().flatMap((f) => walk(join(p, f))) : [p]);
const files = INCLUDE.flatMap((f) => walk(join(root, f)));

const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

const local = [];
const central = [];
let offset = 0;
// Fixed timestamp (2026-01-01) so builds are reproducible.
const DOS_TIME = 0, DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;
for (const f of files) {
  const name = Buffer.from(relative(root, f).split("\\").join("/"));
  const data = readFileSync(f);
  const comp = deflateRawSync(data, { level: 9 });
  const crc = crc32(data);
  const h = Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(0x0800, 6); h.writeUInt16LE(8, 8);
  h.writeUInt16LE(DOS_TIME, 10); h.writeUInt16LE(DOS_DATE, 12); h.writeUInt32LE(crc, 14);
  h.writeUInt32LE(comp.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(name.length, 26);
  local.push(h, name, comp);
  const c = Buffer.alloc(46);
  c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0x0800, 8); c.writeUInt16LE(8, 10);
  c.writeUInt16LE(DOS_TIME, 12); c.writeUInt16LE(DOS_DATE, 14); c.writeUInt32LE(crc, 16); c.writeUInt32LE(comp.length, 20);
  c.writeUInt32LE(data.length, 24); c.writeUInt16LE(name.length, 28); c.writeUInt32LE(offset, 42);
  central.push(c, name);
  offset += h.length + name.length + comp.length;
}
const cd = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
mkdirSync(join(root, "dist"), { recursive: true });
const out = join(root, "dist", `osint-lens-${version}.zip`);
writeFileSync(out, Buffer.concat([...local, cd, end]));
console.log(`✓ ${relative(root, out)} (${files.length} files, ${(statSync(out).size / 1024).toFixed(0)} KB)`);
