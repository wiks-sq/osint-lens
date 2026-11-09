// Favicon fingerprints. Internet-wide scanners (Shodan, FOFA, ZoomEye, Censys)
// index the favicon of every web server they crawl, so the hash of a site's
// favicon finds other servers with the same icon: staging hosts, the origin
// server behind a CDN, other phishing kits built from the same template.
//
// Shodan's "http.favicon.hash" is MurmurHash3 (x86, 32-bit, seed 0, signed) of
// the favicon's base64 encoding *with a newline every 76 characters and at the
// end* (Python's base64.encodebytes).

import { bytesToBase64, digestHex, toHex } from "./util.js";

/** MurmurHash3 x86 32-bit over bytes. Returns a signed 32-bit integer like Python's mmh3.hash. */
export function murmur3(bytes, seed = 0) {
  const len = bytes.length;
  const nblocks = len >> 2;
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  for (let i = 0; i < nblocks; i++) {
    const o = i * 4;
    let k = bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24);
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0;
  const tail = nblocks * 4;
  switch (len & 3) {
    case 3: k ^= bytes[tail + 2] << 16; // falls through
    case 2: k ^= bytes[tail + 1] << 8; // falls through
    case 1:
      k ^= bytes[tail];
      k = Math.imul(k, c1);
      k = (k << 15) | (k >>> 17);
      k = Math.imul(k, c2);
      h ^= k;
  }
  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h | 0;
}

/** Python base64.encodebytes(): newline every 76 chars and a trailing newline. */
export function encodebytes(bytes) {
  const b64 = bytesToBase64(bytes);
  return b64.replace(/.{1,76}/g, "$&\n");
}

/** MD5 (needed because some services index favicons by MD5). Compact RFC 1321 implementation. */
export function md5(bytes) {
  const K = new Int32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) | 0;
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const len = bytes.length;
  const padded = new Uint8Array(((len + 8) >> 6) * 64 + 64);
  padded.set(bytes);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, (len * 8) >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor((len * 8) / 2 ** 32), true);
  let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
  for (let off = 0; off < padded.length; off += 64) {
    const M = (i) => dv.getInt32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      const s = S[(i >> 4) * 4 + (i % 4)];
      const tmp = D;
      D = C;
      C = B;
      const x = (A + F + K[i] + M(g)) | 0;
      B = (B + ((x << s) | (x >>> (32 - s)))) | 0;
      A = tmp;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((v, i) => odv.setInt32(i * 4, v, true));
  return toHex(out);
}

/**
 * Compute every favicon fingerprint we know search engines use.
 * @param {Uint8Array} bytes
 */
export async function faviconHashes(bytes) {
  const b64nl = new TextEncoder().encode(encodebytes(bytes));
  const mmh3 = murmur3(b64nl);
  const sha256 = await digestHex("SHA-256", bytes);
  const hex = md5(bytes);
  return {
    mmh3,
    md5: hex,
    sha256,
    size: bytes.length,
    queries: {
      shodan: `http.favicon.hash:${mmh3}`,
      fofa: `icon_hash="${mmh3}"`,
      zoomeye: `iconhash:"${hex}"`,
      censys: `web.endpoints.http.favicons.hash_sha256: "${sha256}"`,
      criminalip: `favicon: ${mmh3}`
    }
  };
}
