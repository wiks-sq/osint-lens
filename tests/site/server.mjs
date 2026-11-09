// Tiny static server for the browser tests: serves this folder plus the binary fixtures.
import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "fixtures");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".txt": "text/plain", ".xml": "application/xml", ".ico": "image/x-icon", ".jpg": "image/jpeg", ".png": "image/png", ".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".css": "text/css" };
export function start(port = 8790) {
  const srv = http.createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    let file = path === "/" ? join(here, "index.html") : path.startsWith("/files/") ? join(fixtures, path.slice(7)) : path === "/favicon.ico" ? join(fixtures, "favicon.ico") : path === "/.well-known/security.txt" ? join(here, "security.txt") : join(here, path.replace(/^\/static\//, "/"));
    if (path.includes("..") || !existsSync(file) || path.endsWith(".mjs")) {
      if (/jquery/.test(path)) return res.writeHead(200, { "content-type": "text/javascript" }), res.end("/*! jQuery v3.4.1 */ window.jQuery = window.$ = function(){}; jQuery.fn = { jquery: '3.4.1' };");
      res.writeHead(404, { "content-type": "text/html" });
      return res.end("<h1>Not found</h1>");
    }
    res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream", server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3", "x-frame-options": "SAMEORIGIN" });
    res.end(readFileSync(file));
  });
  return new Promise((r) => srv.listen(port, "127.0.0.1", () => r(srv)));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) start().then(() => console.log("test site on http://127.0.0.1:8790/"));
