// Image metadata: EXIF (incl. GPS), XMP and IPTC from JPEG, PNG, WebP and TIFF.
// Pure JS, no dependencies.
//
// Photos published online often still carry where they were taken, the
// camera's serial number, the owner's name, the editing software and the
// original document ID (which links crops and edits back to one source file).

const TAGS = {
  ifd0: {
    0x010e: "ImageDescription", 0x010f: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "ModifyDate",
    0x013b: "Artist", 0x013c: "HostComputer", 0x8298: "Copyright", 0x9c9b: "XPTitle", 0x9c9c: "XPComment",
    0x9c9d: "XPAuthor", 0x9c9e: "XPKeywords", 0x9c9f: "XPSubject", 0x0112: "Orientation"
  },
  exif: {
    0x9003: "DateTimeOriginal", 0x9004: "CreateDate", 0x9010: "OffsetTime", 0x9011: "OffsetTimeOriginal",
    0xa420: "ImageUniqueID", 0xa430: "CameraOwnerName", 0xa431: "BodySerialNumber", 0xa432: "LensSpecification",
    0xa433: "LensMake", 0xa434: "LensModel", 0xa435: "LensSerialNumber", 0x9286: "UserComment",
    0x829a: "ExposureTime", 0x829d: "FNumber", 0x8827: "ISO", 0x920a: "FocalLength", 0xa002: "PixelXDimension",
    0xa003: "PixelYDimension", 0xa405: "FocalLengthIn35mm"
  },
  gps: {
    0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude", 0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef", 0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp", 0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection", 0x0012: "GPSMapDatum", 0x001d: "GPSDateStamp"
  }
};

/** Fields that identify a person, a device or a place. */
export const SENSITIVE_FIELDS = new Set([
  "Artist", "XPAuthor", "CameraOwnerName", "BodySerialNumber", "LensSerialNumber", "HostComputer", "GPSLatitude",
  "GPSLongitude", "GPS position", "Copyright", "creator", "By-line", "Owner", "DocumentID", "OriginalDocumentID",
  "Credit", "City", "Location", "Country", "Sub-location", "Province-State", "Contact", "rights", "SerialNumber",
  "CameraSerialNumber", "OwnerName", "Author", "Comment", "Description", "UserComment"
]);

const TYPE_SIZE = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8];

function readIfd(dv, tiffStart, offset, little, names, out, depth = 0) {
  const pointers = {};
  if (offset < 0 || tiffStart + offset + 2 > dv.byteLength || depth > 4) return pointers;
  const count = dv.getUint16(tiffStart + offset, little);
  for (let i = 0; i < count && i < 500; i++) {
    const e = tiffStart + offset + 2 + i * 12;
    if (e + 12 > dv.byteLength) break;
    const tag = dv.getUint16(e, little);
    const type = dv.getUint16(e + 2, little);
    const n = dv.getUint32(e + 4, little);
    const size = (TYPE_SIZE[type] || 1) * n;
    const valOff = size <= 4 ? e + 8 : tiffStart + dv.getUint32(e + 8, little);
    if (tag === 0x8769 || tag === 0x8825 || tag === 0xa005) {
      pointers[tag] = dv.getUint32(e + 8, little);
      continue;
    }
    const name = names[tag];
    if (!name || valOff + size > dv.byteLength) continue;
    out[name] = readValue(dv, valOff, type, n, little, name);
  }
  return pointers;
}

function readValue(dv, off, type, n, little, name) {
  const arr = [];
  if (type === 2) {
    let s = "";
    for (let i = 0; i < n; i++) {
      const c = dv.getUint8(off + i);
      if (!c) break;
      s += String.fromCharCode(c);
    }
    return decodeUtf8Maybe(s).trim();
  }
  if ((type === 1 || type === 7) && /^XP/.test(name)) {
    // Windows XP* tags are UCS-2 little-endian.
    let s = "";
    for (let i = 0; i + 1 < n; i += 2) {
      const c = dv.getUint16(off + i, true);
      if (!c) break;
      s += String.fromCharCode(c);
    }
    return s.trim();
  }
  if (type === 7 && name === "UserComment") {
    let s = "";
    for (let i = 8; i < n; i++) {
      const c = dv.getUint8(off + i);
      if (c) s += String.fromCharCode(c);
    }
    return s.trim();
  }
  for (let i = 0; i < Math.min(n, 16); i++) {
    switch (type) {
      case 1: case 7: arr.push(dv.getUint8(off + i)); break;
      case 3: arr.push(dv.getUint16(off + i * 2, little)); break;
      case 4: arr.push(dv.getUint32(off + i * 4, little)); break;
      case 9: arr.push(dv.getInt32(off + i * 4, little)); break;
      case 5: { const d = dv.getUint32(off + i * 8 + 4, little); arr.push(d ? dv.getUint32(off + i * 8, little) / d : 0); break; }
      case 10: { const d = dv.getInt32(off + i * 8 + 4, little); arr.push(d ? dv.getInt32(off + i * 8, little) / d : 0); break; }
      default: arr.push(dv.getUint8(off + i));
    }
  }
  return arr.length === 1 ? arr[0] : arr;
}

function decodeUtf8Maybe(s) {
  try {
    return /[\x80-\xff]/.test(s) ? new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(s, (c) => c.charCodeAt(0))) : s;
  } catch {
    return s;
  }
}

/** Parse a TIFF structure (EXIF payload) starting at `start`. */
export function parseTiff(bytes, start = 0) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (start + 8 > dv.byteLength) return null;
  const order = dv.getUint16(start);
  const little = order === 0x4949;
  if (!little && order !== 0x4d4d) return null;
  if (dv.getUint16(start + 2, little) !== 42) return null;
  const ifd0 = {}, exif = {}, gps = {};
  const p = readIfd(dv, start, dv.getUint32(start + 4, little), little, TAGS.ifd0, ifd0);
  if (p[0x8769]) readIfd(dv, start, p[0x8769], little, TAGS.exif, exif, 1);
  if (p[0x8825]) readIfd(dv, start, p[0x8825], little, TAGS.gps, gps, 1);
  return { ifd0, exif, gps };
}

/** Convert EXIF GPS fields to decimal degrees. */
export function gpsToDecimal(gps) {
  const dms = (v, ref) => {
    if (!Array.isArray(v) || v.length < 2) return null;
    const d = v[0] + (v[1] || 0) / 60 + (v[2] || 0) / 3600;
    return /[SW]/i.test(ref || "") ? -d : d;
  };
  const lat = dms(gps.GPSLatitude, gps.GPSLatitudeRef);
  const lon = dms(gps.GPSLongitude, gps.GPSLongitudeRef);
  if (lat == null || lon == null || (lat === 0 && lon === 0) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  const out = { lat: +lat.toFixed(6), lon: +lon.toFixed(6) };
  if (typeof gps.GPSAltitude === "number") out.alt = +(gps.GPSAltitudeRef === 1 ? -gps.GPSAltitude : gps.GPSAltitude).toFixed(1);
  return out;
}

/** Pull interesting fields out of an XMP packet with regexes (XMP is RDF/XML; a full parser isn't needed). */
export function parseXmp(xml) {
  const out = {};
  const grab = (name, re) => {
    const m = re.exec(xml);
    if (m) out[name] = squashXml(m[1]);
  };
  const tags = [
    ["creator", "dc:creator"], ["rights", "dc:rights"], ["title", "dc:title"], ["description", "dc:description"],
    ["subject", "dc:subject"], ["CreatorTool", "xmp:CreatorTool"], ["CreateDate", "xmp:CreateDate"], ["ModifyDate", "xmp:ModifyDate"],
    ["DocumentID", "xmpMM:DocumentID"], ["OriginalDocumentID", "xmpMM:OriginalDocumentID"], ["InstanceID", "xmpMM:InstanceID"],
    ["Credit", "photoshop:Credit"], ["City", "photoshop:City"], ["State", "photoshop:State"], ["Country", "photoshop:Country"],
    ["AuthorsPosition", "photoshop:AuthorsPosition"], ["Location", "Iptc4xmpCore:Location"], ["CountryCode", "Iptc4xmpCore:CountryCode"],
    ["GPSLatitude", "exif:GPSLatitude"], ["GPSLongitude", "exif:GPSLongitude"], ["SerialNumber", "aux:SerialNumber"],
    ["Lens", "aux:Lens"], ["OwnerName", "aux:OwnerName"], ["CameraSerialNumber", "exifEX:BodySerialNumber"], ["Producer", "pdf:Producer"],
    ["Author", "pdf:Author"], ["Keywords", "pdf:Keywords"], ["Rating", "xmp:Rating"], ["Label", "xmp:Label"]
  ];
  for (const [name, tag] of tags) {
    const esc = tag.replace(":", "\\:");
    grab(name, new RegExp(`${esc}="([^"]{1,500})"`));
    if (!out[name]) grab(name, new RegExp(`<${esc}>([\\s\\S]{1,2000}?)</${esc}>`));
  }
  const agents = [...xml.matchAll(/stEvt:softwareAgent="([^"]{1,200})"|<stEvt:softwareAgent>([^<]{1,200})</g)].map((m) => m[1] || m[2]);
  if (agents.length) out.EditHistory = [...new Set(agents)].join("; ");
  return out;
}

const squashXml = (s) =>
  s.replace(/<[^>]+>/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();

/** XMP GPS "60,10.1912N" -> decimal. */
function xmpCoord(v) {
  const m = /^(\d+),(\d+(?:\.\d+)?)(?:,(\d+(?:\.\d+)?))?([NSEW])$/.exec(String(v || "").trim());
  if (!m) return null;
  const d = Number(m[1]) + Number(m[2]) / 60 + Number(m[3] || 0) / 3600;
  return /[SW]/.test(m[4]) ? -d : d;
}

/** IPTC-IIM records in a Photoshop APP13 block. */
function parseIptc(bytes) {
  const names = { 5: "ObjectName", 25: "Keywords", 80: "By-line", 85: "By-lineTitle", 90: "City", 92: "Sub-location", 95: "Province-State", 101: "Country", 105: "Headline", 110: "Credit", 115: "Source", 116: "CopyrightNotice", 118: "Contact", 120: "Caption", 122: "Writer" };
  const out = {};
  for (let i = 0; i + 5 < bytes.length; i++) {
    if (bytes[i] !== 0x1c || bytes[i + 1] !== 2) continue;
    const ds = bytes[i + 2];
    const len = (bytes[i + 3] << 8) | bytes[i + 4];
    if (len > 2000 || i + 5 + len > bytes.length) continue;
    const name = names[ds];
    if (name) {
      const v = new TextDecoder().decode(bytes.subarray(i + 5, i + 5 + len)).trim();
      out[name] = out[name] ? `${out[name]}, ${v}` : v;
    }
    i += 4 + len;
  }
  return out;
}

async function inflate(bytes, format = "deflate") {
  if (typeof DecompressionStream === "undefined") return null;
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Detect the image format from magic bytes. */
export function sniffImage(b) {
  if (b[0] === 0xff && b[1] === 0xd8) return "jpeg";
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "png";
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45) return "webp";
  if ((b[0] === 0x49 && b[1] === 0x49 && b[2] === 42) || (b[0] === 0x4d && b[1] === 0x4d && b[3] === 42)) return "tiff";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return "gif";
  if (b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) return "heif/avif";
  if (b[0] === 0x3c) return "svg/xml";
  return "unknown";
}

/**
 * Extract metadata from image bytes.
 * @param {Uint8Array} bytes
 * @returns {Promise<{format, fields: Array<{group,name,value,sensitive}>, gps: object|null}>}
 */
export async function parseImageMetadata(bytes) {
  const format = sniffImage(bytes);
  const groups = { EXIF: {}, GPS: {}, XMP: {}, IPTC: {}, PNG: {} };
  let tiff = null;
  const latin1 = (a, b) => String.fromCharCode.apply(null, bytes.subarray(a, b));

  if (format === "jpeg") {
    let i = 2;
    while (i + 4 < bytes.length) {
      if (bytes[i] !== 0xff) break;
      const marker = bytes[i + 1];
      if (marker === 0xda || marker === 0xd9) break; // start of scan / end
      const len = (bytes[i + 2] << 8) | bytes[i + 3];
      const s = i + 4, e = i + 2 + len;
      if (marker === 0xe1 && latin1(s, s + 6) === "Exif\0\0") tiff = parseTiff(bytes, s + 6);
      else if (marker === 0xe1 && latin1(s, s + 28).startsWith("http://ns.adobe.com/xap/1.0/")) Object.assign(groups.XMP, parseXmp(new TextDecoder().decode(bytes.subarray(s + 29, e))));
      else if (marker === 0xed) Object.assign(groups.IPTC, parseIptc(bytes.subarray(s, e)));
      else if (marker === 0xfe) groups.EXIF.Comment = new TextDecoder().decode(bytes.subarray(s, e)).trim();
      i = e;
    }
  } else if (format === "png") {
    let i = 8;
    while (i + 12 <= bytes.length) {
      const len = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
      const type = latin1(i + 4, i + 8);
      const d = bytes.subarray(i + 8, i + 8 + len);
      if (type === "tEXt") {
        const z = d.indexOf(0);
        groups.PNG[latin1(i + 8, i + 8 + z)] = new TextDecoder("latin1").decode(d.subarray(z + 1));
      } else if (type === "zTXt") {
        const z = d.indexOf(0);
        const txt = await inflate(d.subarray(z + 2)).catch(() => null);
        if (txt) groups.PNG[latin1(i + 8, i + 8 + z)] = new TextDecoder("latin1").decode(txt);
      } else if (type === "iTXt") {
        const z = d.indexOf(0);
        const key = latin1(i + 8, i + 8 + z);
        const compressed = d[z + 1] === 1;
        let p = z + 3;
        p = d.indexOf(0, p) + 1; // language tag
        p = d.indexOf(0, p) + 1; // translated keyword
        let txt = d.subarray(p);
        if (compressed) txt = (await inflate(txt).catch(() => null)) || new Uint8Array();
        const s = new TextDecoder().decode(txt);
        if (key === "XML:com.adobe.xmp") Object.assign(groups.XMP, parseXmp(s));
        else groups.PNG[key] = s;
      } else if (type === "eXIf") {
        tiff = parseTiff(d, 0);
      } else if (type === "IEND") break;
      i += 12 + len;
    }
  } else if (format === "webp") {
    let i = 12;
    while (i + 8 <= bytes.length) {
      const type = latin1(i, i + 4);
      const len = bytes[i + 4] | (bytes[i + 5] << 8) | (bytes[i + 6] << 16) | (bytes[i + 7] << 24);
      const d = bytes.subarray(i + 8, i + 8 + len);
      if (type === "EXIF") tiff = parseTiff(d, latin1(i + 8, i + 14) === "Exif\0\0" ? 6 : 0);
      if (type === "XMP ") Object.assign(groups.XMP, parseXmp(new TextDecoder().decode(d)));
      i += 8 + len + (len & 1);
    }
  } else if (format === "tiff") {
    tiff = parseTiff(bytes, 0);
  }

  // Some files carry XMP outside the usual containers (e.g. GIF, SVG).
  if (!Object.keys(groups.XMP).length && bytes.length < 8e6) {
    const head = new TextDecoder("latin1").decode(bytes.subarray(0, Math.min(bytes.length, 2e6)));
    const x = head.indexOf("<x:xmpmeta");
    if (x >= 0) Object.assign(groups.XMP, parseXmp(head.slice(x, head.indexOf("</x:xmpmeta>", x) + 12)));
  }

  let gps = null;
  if (tiff) {
    Object.assign(groups.EXIF, tiff.ifd0, tiff.exif);
    Object.assign(groups.GPS, tiff.gps);
    gps = gpsToDecimal(tiff.gps);
  }
  if (!gps && groups.XMP.GPSLatitude) {
    const lat = xmpCoord(groups.XMP.GPSLatitude), lon = xmpCoord(groups.XMP.GPSLongitude);
    if (lat != null && lon != null) gps = { lat: +lat.toFixed(6), lon: +lon.toFixed(6) };
  }

  const fields = [];
  for (const [group, obj] of Object.entries(groups)) {
    for (const [name, value] of Object.entries(obj)) {
      if (value === "" || value == null) continue;
      if (group === "GPS" && /^GPS(Latitude|Longitude)(Ref)?$/.test(name)) continue;
      const v = Array.isArray(value) ? value.map((x) => (typeof x === "number" ? +x.toFixed(4) : x)).join(", ") : typeof value === "number" ? +value.toFixed(4) : String(value);
      fields.push({ group, name, value: v.length > 500 ? `${v.slice(0, 500)}…` : v, sensitive: SENSITIVE_FIELDS.has(name) });
    }
  }
  if (gps) fields.unshift({ group: "GPS", name: "GPS position", value: `${gps.lat}, ${gps.lon}${gps.alt != null ? ` (alt ${gps.alt} m)` : ""}`, sensitive: true });
  return { format, fields, gps };
}
