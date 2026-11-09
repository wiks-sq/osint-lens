// Document metadata: PDF, Office Open XML (docx/xlsx/pptx) and OpenDocument.
//
// Published documents routinely leak author names, user names on the author's
// machine (inside template and file paths), the organisation, the software
// and its version, internal file-server paths, tracked-change and comment
// authors, total editing time and revision counts.

import { listZip, readZipText } from "./zip.js";
import { parseXmp, SENSITIVE_FIELDS } from "./exif.js";

const latin1 = (b) => {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return s;
};

/** Decode a PDF literal string body (between the parentheses). */
export function pdfLiteral(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== "\\") {
      out += c;
      continue;
    }
    const n = s[++i];
    const map = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", "(": "(", ")": ")", "\\": "\\" };
    if (n in map) out += map[n];
    else if (/[0-7]/.test(n)) {
      let oct = n;
      while (oct.length < 3 && /[0-7]/.test(s[i + 1])) oct += s[++i];
      out += String.fromCharCode(parseInt(oct, 8));
    } else if (n === "\r" || n === "\n") {
      if (n === "\r" && s[i + 1] === "\n") i++;
    } else out += n || "";
  }
  return decodePdfText(out);
}

/** PDF text strings are PDFDocEncoding or UTF-16BE with a BOM. */
function decodePdfText(raw) {
  if (raw.charCodeAt(0) === 0xfe && raw.charCodeAt(1) === 0xff) {
    let s = "";
    for (let i = 2; i + 1 < raw.length; i += 2) s += String.fromCharCode((raw.charCodeAt(i) << 8) | raw.charCodeAt(i + 1));
    return s;
  }
  if (raw.charCodeAt(0) === 0xef && raw.charCodeAt(1) === 0xbb && raw.charCodeAt(2) === 0xbf) {
    try {
      return new TextDecoder().decode(Uint8Array.from(raw.slice(3), (c) => c.charCodeAt(0)));
    } catch {
      /* fall through */
    }
  }
  return raw.replace(/\xae/g, "®");
}

/** "D:20230115093000+02'00'" -> ISO 8601. */
export function pdfDate(s) {
  const m = /D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+\-])?(\d{2})?'?(\d{2})?/.exec(s || "");
  if (!m) return s;
  const [, y, mo = "01", d = "01", h = "00", mi = "00", se = "00", tz, th, tm] = m;
  const zone = !tz || /z/i.test(tz) ? "Z" : `${tz}${th || "00"}:${tm || "00"}`;
  return `${y}-${mo}-${d}T${h}:${mi}:${se}${zone}`;
}

const PDF_KEYS = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate", "Company", "SourceModified", "Trapped"];

function readPdfDict(text, fields) {
  for (const key of PDF_KEYS) {
    if (fields[key]) continue;
    const re = new RegExp(`/${key}\\s*(\\((?:\\\\.|[^\\\\)])*\\)|<[0-9A-Fa-f\\s]*>)`, "g");
    for (const m of text.matchAll(re)) {
      let v = m[1];
      if (v.startsWith("(")) v = pdfLiteral(v.slice(1, -1));
      else {
        const hex = v.slice(1, -1).replace(/\s+/g, "");
        let raw = "";
        for (let i = 0; i + 1 < hex.length; i += 2) raw += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        v = decodePdfText(raw);
      }
      v = v.replace(/\0/g, "").trim();
      if (v) {
        fields[key] = /Date$/.test(key) ? pdfDate(v) : v;
        break;
      }
    }
  }
}

async function inflateZlib(bytes) {
  if (typeof DecompressionStream === "undefined") return null;
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

/** PDF metadata from the Info dictionary, XMP and (PDF 1.5+) compressed object streams. */
export async function parsePdf(bytes) {
  const text = latin1(bytes);
  const fields = {};
  readPdfDict(text, fields);
  const version = (/%PDF-(\d\.\d)/.exec(text.slice(0, 1024)) || [])[1] || null;

  // XMP packet (often uncompressed).
  let xmp = {};
  const x = text.indexOf("<x:xmpmeta");
  if (x >= 0) xmp = parseXmp(text.slice(x, text.indexOf("</x:xmpmeta>", x) + 12));

  // Compressed streams: the Info dictionary may live inside an object stream.
  if (Object.keys(fields).length < 3) {
    let inflated = 0;
    for (const m of text.matchAll(/\/FlateDecode[\s\S]{0,300}?stream\r?\n/g)) {
      if (inflated++ > 40) break;
      const start = m.index + m[0].length;
      const end = text.indexOf("endstream", start);
      if (end < 0 || end - start > 2e6) continue;
      const out = await inflateZlib(bytes.subarray(start, end));
      if (!out) continue;
      const s = latin1(out);
      if (/\/(Author|Producer|Creator)\s*[(<]/.test(s)) readPdfDict(s, fields);
      if (!Object.keys(xmp).length && s.includes("<x:xmpmeta")) xmp = parseXmp(s);
    }
  }
  const encrypted = /\/Encrypt\s+\d+\s+\d+\s+R/.test(text);
  const pages = (text.match(/\/Type\s*\/Page(?![s\w])/g) || []).length || null;
  const js = /\/JavaScript|\/JS\s*[(<]/.test(text);
  const launch = /\/Launch\b/.test(text);
  const embedded = /\/EmbeddedFile\b/.test(text);
  const warnings = [];
  if (js) warnings.push("Contains JavaScript");
  if (launch) warnings.push("Contains a Launch action (can start programs)");
  if (embedded) warnings.push("Contains embedded files");
  if (encrypted) warnings.push("Encrypted (metadata may be unreadable)");
  return { format: "pdf", version, pages, fields, xmp, warnings };
}

const xmlText = (xml, tag) => {
  const m = new RegExp(`<(?:[\\w]+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[\\w]+:)?${tag}>`).exec(xml || "");
  return m ? m[1].replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim() : null;
};

/** Windows/UNC/macOS/Linux paths that reveal user names and file servers. */
export function findPaths(text) {
  const out = new Set();
  const re = /(?:[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\0]{1,80}\\){1,12}[^\\/:*?"<>|\r\n\0]{0,80}|\\\\[A-Za-z0-9.\-_$]{2,60}\\[^\s"<>|]{2,200}|\/(?:Users|home)\/[A-Za-z0-9._\-]{2,40}\/[^\s"<>]{0,200}|file:\/\/\/?[^\s"<>]{3,200})/g;
  for (const m of String(text).matchAll(re)) out.add(m[0].replace(/&amp;/g, "&").replace(/["']+$/, ""));
  return [...out].slice(0, 25);
}

/** User names inside paths ("C:\Users\jdoe\..." -> "jdoe"). */
export function usersFromPaths(paths) {
  const out = new Set();
  for (const p of paths) {
    const m = /(?:\\Users\\|\\Documents and Settings\\|\/Users\/|\/home\/)([^\\/]{2,40})/i.exec(p);
    if (m && !/^(public|default|all users|shared)$/i.test(m[1])) out.add(m[1]);
  }
  return [...out];
}

/** OOXML (docx/xlsx/pptx) and ODF (odt/ods/odp) metadata. */
export async function parseOfficeZip(bytes) {
  const entries = listZip(bytes);
  if (!entries) return null;
  const names = entries.map((e) => e.name);
  const fields = {};
  const authors = new Set();
  let format = "zip";
  let allXml = "";

  if (names.includes("docProps/core.xml") || names.includes("[Content_Types].xml")) {
    format = names.some((n) => n.startsWith("word/")) ? "docx" : names.some((n) => n.startsWith("xl/")) ? "xlsx" : names.some((n) => n.startsWith("ppt/")) ? "pptx" : "ooxml";
    const core = (await readZipText(bytes, entries, "docProps/core.xml")) || "";
    const app = (await readZipText(bytes, entries, "docProps/app.xml")) || "";
    const custom = (await readZipText(bytes, entries, "docProps/custom.xml")) || "";
    for (const [k, tag] of [["Title", "title"], ["Subject", "subject"], ["Creator", "creator"], ["LastModifiedBy", "lastModifiedBy"], ["Created", "created"], ["Modified", "modified"], ["LastPrinted", "lastPrinted"], ["Revision", "revision"], ["Keywords", "keywords"], ["Category", "category"], ["Description", "description"], ["ContentStatus", "contentStatus"]]) {
      const v = xmlText(core, tag);
      if (v) fields[k] = v;
    }
    for (const [k, tag] of [["Application", "Application"], ["AppVersion", "AppVersion"], ["Company", "Company"], ["Manager", "Manager"], ["Template", "Template"], ["TotalEditingMinutes", "TotalTime"], ["Pages", "Pages"], ["Words", "Words"], ["Slides", "Slides"], ["HyperlinkBase", "HyperlinkBase"]]) {
      const v = xmlText(app, tag);
      if (v) fields[k] = v;
    }
    for (const m of custom.matchAll(/<property[^>]*name="([^"]+)"[^>]*>([\s\S]*?)<\/property>/g)) {
      const v = m[2].replace(/<[^>]+>/g, "").trim();
      if (v) fields[`Custom: ${m[1]}`] = v.slice(0, 300);
    }
    allXml += core + app + custom;
    // Authors of tracked changes, comments and co-authoring.
    const scan = names.filter((n) => /^(word\/(document|comments|commentsExtended|people|settings|footnotes|endnotes)|xl\/(workbook|comments\d*|persons\/person|threadedComments\/[^/]+)|ppt\/(commentAuthors|presentation|comments\/[^/]+))\.xml$|_rels\/.*\.rels$|xl\/externalLinks\//.test(n)).slice(0, 40);
    for (const n of scan) {
      const t = (await readZipText(bytes, entries, n)) || "";
      allXml += t;
      for (const m of t.matchAll(/(?:w:author|author|displayName|name)="([^"]{2,80})"/g)) {
        if (/\.(xml|rels)$|^rId\d+$|^_x|^Sheet\d|Normal|Default|Heading/.test(m[1])) continue;
        if (/w:author|author/.test(m[0]) || /people|person|commentAuthors/.test(n)) authors.add(m[1]);
      }
      const abs = /absPath[^>]*url="([^"]+)"/.exec(t);
      if (abs) fields["Saved from path"] = abs[1];
    }
    const hiddenSheets = (allXml.match(/<sheet [^>]*state="(?:hidden|veryHidden)"/g) || []).length;
    if (hiddenSheets) fields["Hidden sheets"] = String(hiddenSheets);
    if (names.some((n) => /vbaProject\.bin$/i.test(n))) fields.Macros = "Yes (VBA project present)";
  } else if (names.includes("meta.xml") || names.includes("mimetype")) {
    const mime = (await readZipText(bytes, entries, "mimetype")) || "";
    format = /text/.test(mime) ? "odt" : /spreadsheet/.test(mime) ? "ods" : /presentation/.test(mime) ? "odp" : "odf";
    const meta = (await readZipText(bytes, entries, "meta.xml")) || "";
    allXml += meta;
    for (const [k, tag] of [["Title", "title"], ["InitialCreator", "initial-creator"], ["Creator", "creator"], ["Created", "creation-date"], ["Modified", "date"], ["Generator", "generator"], ["EditingCycles", "editing-cycles"], ["EditingDuration", "editing-duration"], ["PrintedBy", "printed-by"], ["Keywords", "keyword"], ["Subject", "subject"]]) {
      const v = xmlText(meta, tag);
      if (v) fields[k] = v;
    }
    const content = (await readZipText(bytes, entries, "content.xml")) || "";
    for (const m of content.matchAll(/<dc:creator>([^<]{2,80})<\/dc:creator>/g)) authors.add(m[1]);
  } else {
    return { format: "zip", entries: names.slice(0, 200), fields: {}, authors: [], paths: [], users: [], warnings: [] };
  }

  const paths = findPaths(allXml);
  for (const v of Object.values(fields)) for (const p of findPaths(v)) if (!paths.includes(p)) paths.push(p);
  const users = usersFromPaths(paths);
  const warnings = [];
  if (fields.Macros) warnings.push("Contains macros");
  if (fields["Hidden sheets"]) warnings.push(`${fields["Hidden sheets"]} hidden sheet(s)`);
  return { format, fields, authors: [...authors].slice(0, 50), paths, users, warnings };
}

/** Sniff and parse any supported document. */
export async function parseDocument(bytes) {
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    const r = await parsePdf(bytes);
    const paths = findPaths(Object.values(r.fields).join("\n") + JSON.stringify(r.xmp));
    return { ...r, authors: [r.fields.Author, r.xmp.creator].filter(Boolean), paths, users: usersFromPaths(paths) };
  }
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) return parseOfficeZip(bytes);
  if (bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) {
    // Legacy OLE2 (.doc/.xls/.ppt): pull printable strings that look like metadata.
    const text = latin1(bytes.subarray(0, Math.min(bytes.length, 4e6)));
    const paths = findPaths(text);
    return { format: "ole2 (legacy Office)", fields: {}, authors: [], paths, users: usersFromPaths(paths), warnings: ["Legacy binary format: only file paths were extracted"] };
  }
  return null;
}

/** Flatten a parsed document into display rows. */
export function docRows(doc) {
  if (!doc) return [];
  const rows = Object.entries(doc.fields || {}).map(([name, value]) => ({ group: "Document", name, value: String(value), sensitive: /creator|author|modified ?by|company|manager|template|path|printed|custom/i.test(name) }));
  for (const [name, value] of Object.entries(doc.xmp || {})) rows.push({ group: "XMP", name, value: String(value), sensitive: SENSITIVE_FIELDS.has(name) });
  for (const a of doc.authors || []) rows.push({ group: "People", name: "Author / editor", value: a, sensitive: true });
  for (const p of doc.paths || []) rows.push({ group: "Paths", name: "File path", value: p, sensitive: true });
  for (const u of doc.users || []) rows.push({ group: "People", name: "User account (from path)", value: u, sensitive: true });
  return rows;
}
