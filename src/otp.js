// TOTP / HOTP / Steam Guard (RFC 4226/6238) + otpauth parsing.
// Pure Web-platform APIs (WebCrypto, TextEncoder, atob/btoa). No Node APIs.
import { b64decode } from './crypto.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HASH = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
const td = new TextDecoder();

export function normalizeSecret(s) {
  return String(s).replace(/[\s\-=]/g, '').toUpperCase();
}

export function normalizeAlgorithm(a) {
  const n = String(a || 'SHA1').replace(/-/g, '').toUpperCase();
  if (n === 'SHA1' || n === 'SHA256' || n === 'SHA512') return n;
  throw new Error(`unknown algorithm "${a}" (use SHA1, SHA256, or SHA512)`);
}

export function base32Decode(s) {
  const cleaned = String(s).toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of cleaned) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character "${ch}"`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function counterBytes(counter) {
  const b = new Uint8Array(8);
  let v = BigInt(Math.trunc(counter));
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

async function hmacBytes(algorithm, keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: HASH[algorithm] }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

function dynamicTruncate(hmac, digits) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return (bin % (10 ** digits)).toString().padStart(digits, '0');
}

export async function hotp(secret, counter, digits, algorithm = 'SHA1') {
  const hmac = await hmacBytes(algorithm, base32Decode(secret), counterBytes(counter));
  return dynamicTruncate(hmac, digits);
}

export async function totp(secret, unix, period, digits, algorithm = 'SHA1') {
  return hotp(secret, Math.floor(unix / period), digits, algorithm);
}

const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export async function steam(secret, unix) {
  const hmac = await hmacBytes('SHA1', base32Decode(secret), counterBytes(Math.floor(unix / 30)));
  const offset = hmac[hmac.length - 1] & 0x0f;
  let n =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  let out = '';
  for (let i = 0; i < 5; i++) {
    out += STEAM_ALPHABET[n % 26];
    n = Math.floor(n / 26);
  }
  return out;
}

export function secondsRemaining(period, now) {
  return period - (now % period);
}

// Percent-encode every byte except ASCII alphanumerics and : - _ . ~
export function pctEncode(s) {
  let out = '';
  for (const ch of String(s)) {
    const c = ch.codePointAt(0);
    if (
      (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) || c === 0x3a || c === 0x2d ||
      c === 0x5f || c === 0x2e || c === 0x7e
    ) {
      out += ch;
    } else {
      for (const byte of new TextEncoder().encode(ch)) {
        out += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// otpauth:// and otpauth-migration:// parsing
// ---------------------------------------------------------------------------

export function parseOtpauth(uri) {
  const m = String(uri).match(/^otpauth:\/\/(totp|hotp)\/([^?]+)\?(.*)$/i);
  if (!m) throw new Error('not a valid otpauth:// URI');
  const kind = m[1].toLowerCase();
  const labelPart = decodeURIComponent(m[2]);
  const qs = new URLSearchParams(m[3]);
  const secret = normalizeSecret(qs.get('secret') || '');
  if (!secret) throw new Error('otpauth URI is missing a secret');
  base32Decode(secret); // validate

  let name = labelPart;
  let issuer = qs.get('issuer') || '';
  const colon = labelPart.indexOf(':');
  if (colon > 0) {
    if (!issuer) issuer = labelPart.slice(0, colon);
    name = labelPart.slice(colon + 1);
  }

  const digits = Number(qs.get('digits') || 6);
  const period = Number(qs.get('period') || 30);
  const algorithm = normalizeAlgorithm(qs.get('algorithm') || 'SHA1');
  const counter = kind === 'hotp' ? Number(qs.get('counter') || 0) : 0;

  return { id: 0, name, issuer, secret, digits, period, algorithm, kind, counter };
}

export function encodeOtpauth(entry) {
  const type = entry.kind === 'hotp' ? 'hotp' : 'totp';
  const lbl = entry.issuer ? `${entry.issuer}:${entry.name}` : entry.name;
  let q = `secret=${pctEncode(normalizeSecret(entry.secret))}`;
  if (entry.issuer) q += `&issuer=${pctEncode(entry.issuer)}`;
  q += `&algorithm=${entry.algorithm}&digits=${entry.digits}&period=${entry.period}`;
  if (entry.kind === 'hotp') q += `&counter=${entry.counter ?? 0}`;
  return `otpauth://${type}/${pctEncode(lbl)}?${q}`;
}

// Minimal protobuf reader for Google Authenticator "transfer accounts" exports.
function readVarint(buf, pos) {
  let result = 0n, shift = 0n, b;
  do {
    b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    shift += 7n;
  } while (b & 0x80);
  return [result, pos];
}

function parseOtpParameters(buf) {
  let secret = new Uint8Array(0), name = '', issuer = '';
  let algorithm = 1, digits = 1, type = 2, counter = 0;
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p2] = readVarint(buf, pos);
    pos = p2;
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      const [v, p3] = readVarint(buf, pos);
      pos = p3;
      if (field === 4) algorithm = Number(v);
      else if (field === 5) digits = Number(v);
      else if (field === 6) type = Number(v);
      else if (field === 7) counter = Number(v);
    } else if (wire === 2) {
      const [len, p3] = readVarint(buf, pos);
      pos = p3;
      const n = Number(len);
      const slice = buf.subarray(pos, pos + n);
      pos += n;
      if (field === 1) secret = slice.slice();
      else if (field === 2) name = td.decode(slice);
      else if (field === 3) issuer = td.decode(slice);
    } else {
      throw new Error(`unsupported protobuf wire type ${wire}`);
    }
  }
  const algMap = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };
  const digitsMap = { 1: 6, 2: 8 };
  const kindMap = { 1: 'hotp', 2: 'totp' };
  const kind = kindMap[type] ?? 'totp';
  return {
    id: 0,
    name: name.replace(/\s+$/, ''), // sample vector has trailing space
    issuer,
    secret: base32Encode(secret),
    digits: digitsMap[digits] ?? 6,
    period: 30,
    algorithm: algMap[algorithm] ?? 'SHA1',
    kind,
    counter: kind === 'hotp' ? counter : 0,
  };
}

export function parseMigration(uri) {
  const m = String(uri).match(/^otpauth-migration:\/\/offline\?data=([^&]+)/i);
  if (!m) throw new Error('not a valid otpauth-migration:// URI');
  const decoded = decodeURIComponent(m[1]);
  const buf = b64decode(decoded);
  const entries = [];
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p2] = readVarint(buf, pos);
    pos = p2;
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 2) {
      const [len, p3] = readVarint(buf, pos);
      pos = p3;
      const n = Number(len);
      const slice = buf.subarray(pos, pos + n);
      pos += n;
      if (field === 1) entries.push(parseOtpParameters(slice));
    } else if (wire === 0) {
      const [, p3] = readVarint(buf, pos);
      pos = p3;
    } else {
      throw new Error(`unsupported protobuf wire type ${wire}`);
    }
  }
  if (entries.length === 0) throw new Error('migration export contained no entries');
  return entries;
}
