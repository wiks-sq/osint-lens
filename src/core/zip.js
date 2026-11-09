// Minimal ZIP reader, enough for Office Open XML and OpenDocument files.
// Uses the platform's DecompressionStream("deflate-raw"), available in Chrome
// (pages and service workers) and Node 18+.

/** List entries from the central directory. */
export function listZip(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // End of central directory: scan back over a possible comment (max 64 KB).
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 65535); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return null;
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const entries = [];
  for (let n = 0; n < count && p + 46 <= bytes.length; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const csize = dv.getUint32(p + 20, true);
    const usize = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const local = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(p + 46, p + 46 + nameLen));
    entries.push({ name, method, csize, usize, local });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** Read one entry's bytes (stored or deflated). Returns null when unsupported. */
export async function readZipEntry(bytes, entry, maxSize = 20e6) {
  if (entry.usize > maxSize) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const p = entry.local;
  if (p + 30 > bytes.length || dv.getUint32(p, true) !== 0x04034b50) return null;
  const start = p + 30 + dv.getUint16(p + 26, true) + dv.getUint16(p + 28, true);
  const data = bytes.subarray(start, start + entry.csize);
  if (entry.method === 0) return data;
  if (entry.method !== 8 || typeof DecompressionStream === "undefined") return null;
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Read an entry as UTF-8 text by name. */
export async function readZipText(bytes, entries, name) {
  const e = entries.find((x) => x.name === name);
  if (!e) return null;
  const b = await readZipEntry(bytes, e);
  return b ? new TextDecoder().decode(b) : null;
}
