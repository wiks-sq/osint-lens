// Checksum validators. A pattern alone produces many false positives; where a
// format has a check digit we require it to pass before reporting a match.

/** Luhn (mod 10): payment cards and some ID numbers. */
export function luhn(num) {
  const digits = String(num).replace(/\D/g, "");
  if (digits.length < 12 || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Issuer network from the card number prefix (display only). */
export function cardBrand(num) {
  const d = String(num).replace(/\D/g, "");
  if (/^4/.test(d)) return "Visa";
  if (/^(5[1-5]|2[2-7])/.test(d)) return "Mastercard";
  if (/^3[47]/.test(d)) return "American Express";
  if (/^(6011|65|64[4-9])/.test(d)) return "Discover";
  if (/^35(2[89]|[3-8])/.test(d)) return "JCB";
  if (/^3(0[0-5]|[68])/.test(d)) return "Diners Club";
  if (/^(62|81)/.test(d)) return "UnionPay";
  return "Card";
}

const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22, CY: 28,
  CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18,
  GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32,
  LI: 21, LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24,
  PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SC: 31, SE: 24, SI: 19, SK: 24, SM: 27, ST: 25, SV: 28,
  TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20
};

/** IBAN: country length table + ISO 7064 mod-97. */
export function iban(value) {
  const s = String(value).replace(/\s+/g, "").toUpperCase();
  const len = IBAN_LENGTHS[s.slice(0, 2)];
  if (!len || s.length !== len || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= "A" ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem === 1;
}

/** Finnish personal identity code (henkilötunnus): DDMMYY C NNN X. */
export function finnishHetu(value) {
  const m = /^(\d{2})(\d{2})(\d{2})([-+A-FU-Y])(\d{3})([0-9A-Y])$/i.exec(String(value).trim());
  if (!m) return false;
  const [, dd, mm, , , nnn, check] = m;
  if (Number(dd) < 1 || Number(dd) > 31 || Number(mm) < 1 || Number(mm) > 12) return false;
  const chars = "0123456789ABCDEFHJKLMNPRSTUVWXY";
  return chars[Number(dd + mm + m[3] + nnn) % 31] === check.toUpperCase();
}

/** Finnish business ID (Y-tunnus): NNNNNNN-C, weighted mod 11. */
export function finnishBusinessId(value) {
  const m = /^(\d{7})-(\d)$/.exec(String(value).trim());
  if (!m) return false;
  const w = [7, 9, 10, 5, 8, 4, 2];
  const r = w.reduce((s, x, i) => s + x * Number(m[1][i]), 0) % 11;
  if (r === 1) return false;
  return Number(m[2]) === (r === 0 ? 0 : 11 - r);
}

/** US Social Security number: excludes ranges never issued. */
export function usSsn(value) {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(String(value).trim());
  if (!m) return false;
  const [, a, g, s] = m;
  return a !== "000" && a !== "666" && a[0] !== "9" && g !== "00" && s !== "0000" && !/^(\d)\1{2}-\1{2}-\1{4}$/.test(value);
}

// --- Cryptocurrency addresses ------------------------------------------------

// A compact synchronous SHA-256 so validators stay synchronous. (WebCrypto's
// digest is async, which would make every detector async.)
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

export function sha256Sync(bytes) {
  const l = bytes.length;
  const withPad = new Uint8Array(((l + 9 + 63) >> 6) << 6);
  withPad.set(bytes);
  withPad[l] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 4, l * 8);
  dv.setUint32(withPad.length - 8, Math.floor((l * 8) / 2 ** 32));
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < withPad.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  H.forEach((v, i) => odv.setUint32(i * 4, v));
  return out;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Decode(s) {
  const bytes = [0];
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    let carry = v;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const ch of s) {
    if (ch !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

/** Base58Check (Bitcoin legacy/P2SH, Litecoin, Dogecoin, Tron...): last 4 bytes = double SHA-256. */
export function base58Check(s) {
  const b = base58Decode(s);
  if (!b || b.length < 5) return false;
  const payload = b.subarray(0, -4);
  const sum = sha256Sync(sha256Sync(payload));
  return b.subarray(-4).every((x, i) => x === sum[i]);
}

const BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32Polymod(values) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= G[i];
  }
  return chk >>> 0;
}

/** Bech32 / Bech32m (SegWit and Taproot addresses). Returns the HRP or null. */
export function bech32(addr) {
  const s = String(addr);
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) return null;
  const lower = s.toLowerCase();
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || pos + 7 > lower.length || lower.length > 90) return null;
  const hrp = lower.slice(0, pos);
  const data = [];
  for (const ch of lower.slice(pos + 1)) {
    const v = BECH32.indexOf(ch);
    if (v < 0) return null;
    data.push(v);
  }
  const expanded = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  const pm = bech32Polymod([...expanded, ...data]);
  return pm === 1 || pm === 0x2bc830a3 ? hrp : null;
}
