// Browser end-to-end test: loads the unpacked extension into Chrome, scans the
// local fixture site and checks every view renders without errors.
//
//   npm install            (installs puppeteer-core; it does not download a browser)
//   npm run test:e2e       (uses CHROME_PATH or a locally installed Chrome/Chromium)
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { start } from "../site/server.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const CANDIDATES = [process.env.CHROME_PATH, "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"];
const chromePath = CANDIDATES.find((p) => p && existsSync(p));
let puppeteer;
try {
  puppeteer = (await import("puppeteer-core")).default;
} catch {
  /* optional dependency */
}
const skip = !puppeteer ? "puppeteer-core not installed (run npm install)" : !chromePath ? "no Chrome found (set CHROME_PATH)" : false;

let browser, srv, extId, sw, panel, tabId;
const errors = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  if (skip) return;
  srv = await start(8790);
  browser = await puppeteer.launch({ executablePath: chromePath, headless: true, pipe: true, enableExtensions: [ROOT], args: ["--no-first-run", "--no-default-browser-check"] });
  const swTarget = await browser.waitForTarget((t) => t.type() === "service_worker" && t.url().endsWith("service-worker.js"), { timeout: 20000 });
  extId = new URL(swTarget.url()).host;
  sw = await swTarget.worker();
  const site = await browser.newPage();
  await site.goto("http://127.0.0.1:8790/", { waitUntil: "networkidle2" });
  tabId = await sw.evaluate(async () => (await chrome.tabs.query({})).find((t) => t.url?.startsWith("http://127.0.0.1:8790"))?.id);
  panel = await browser.newPage();
  await panel.setViewport({ width: 460, height: 1000 });
  panel.on("pageerror", (e) => errors.push(e.message));
  panel.on("console", (m) => m.type() === "error" && errors.push(m.text()));
});

after(async () => {
  await browser?.close();
  srv?.close();
});

test("scan produces a full report", { skip, timeout: 90000 }, async () => {
  await panel.goto(`chrome-extension://${extId}/src/ui/sidepanel.html?tabId=${tabId}`);
  await panel.waitForSelector("#scan-btn");
  await panel.click("#scan-btn");
  await panel.waitForSelector(".summary", { timeout: 60000 });
  const r = await panel.evaluate(async () => {
    const db = await import("/src/shared/db.js");
    const [first] = await db.listReports(1);
    return db.getReport(first.id);
  });
  const has = (type, value) => r.indicators.some((i) => i.type === type && i.value === value);
  assert.ok(has("email", "sales@acme-widgets.fi"));
  assert.ok(has("email", "jane.smith@acme-widgets.fi"), "obfuscated email");
  assert.ok(has("tracker", "G-ABC123XYZ9"));
  assert.ok(has("tracker", "ca-pub-1234567890123456"), "AdSense publisher from ads.txt");
  assert.ok(has("verification", "abcDEF123_testVerificationToken"));
  assert.ok(has("coordinates", "60.169857, 24.938379"));
  assert.ok(has("organization", "Acme Widgets Oy"));
  assert.ok(r.exposures.some((e) => e.id === "aws_secret"));
  assert.ok(r.exposures.some((e) => e.id === "url_credential"));
  assert.ok(r.tech.some((t) => t.name === "jQuery" && t.version === "3.4.1" && t.vulns.length));
  assert.ok(r.phishing.signals.some((s) => s.id === "form_external"));
  assert.equal(r.favicon?.mmh3, 1178126473);
  assert.ok(r.wellKnown.robots && r.wellKnown.securityTxt && r.wellKnown.ads && r.wellKnown.sitemap);
  assert.ok(r.js.sourcemaps.length && r.js.buckets.some((b) => b.name === "acme-uploads"));
});

test("every tab renders", { skip, timeout: 60000 }, async () => {
  const labels = await panel.$$eval("#tabbar button", (bs) => bs.map((b) => b.textContent));
  assert.ok(labels.length >= 9);
  for (let i = 0; i < labels.length; i++) {
    await panel.evaluate((i) => document.querySelectorAll("#tabbar button")[i].click(), i);
    await sleep(250);
    const text = await panel.$eval("#content", (e) => e.textContent);
    assert.ok(!text.includes("Couldn't render"), `tab ${labels[i]} failed to render`);
  }
});

test("file metadata analysis", { skip, timeout: 60000 }, async () => {
  const id = await panel.evaluate(async () => (await (await import("/src/shared/db.js")).listReports(1))[0].id);
  await panel.evaluate((reportId, tabId) => chrome.runtime.sendMessage({ type: "files", reportId, tabId, urls: ["http://127.0.0.1:8790/files/photo_gps.jpg", "http://127.0.0.1:8790/files/report.docx", "http://127.0.0.1:8790/files/doc.pdf"] }), id, tabId);
  let r;
  for (let i = 0; i < 40; i++) {
    await sleep(500);
    r = await panel.evaluate(async (id) => (await import("/src/shared/db.js")).getReport(id), id);
    if (r.files?.length === 3) break;
  }
  const jpg = r.files.find((f) => f.url.endsWith(".jpg"));
  assert.ok(jpg.gps && Math.abs(jpg.gps.lat - 60.17) < 0.01);
  assert.ok(r.files.find((f) => f.url.endsWith(".docx")).users.includes("mmeikalainen"));
  assert.ok(r.indicators.some((i) => i.type === "person" && i.value === "John Q. Public"));
});

test("lookup, history and settings pages render", { skip, timeout: 30000 }, async () => {
  await panel.click("#lookup-btn");
  await panel.type("#content textarea", "UA-12345678-1");
  await panel.keyboard.press("Enter");
  await panel.waitForFunction(() => /DNSlytics|PublicWWW/.test(document.body.textContent));
  await panel.click("#history-btn");
  await panel.waitForFunction(() => /Acme Widgets/.test(document.body.textContent));
  const opts = await browser.newPage();
  opts.on("pageerror", (e) => errors.push(e.message));
  await opts.goto(`chrome-extension://${extId}/src/ui/options.html`);
  await opts.waitForSelector("#mcp");
  assert.deepEqual(errors, []);
});
