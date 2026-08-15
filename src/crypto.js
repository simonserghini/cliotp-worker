// Web-platform crypto primitives — no Node APIs. Runs in Workers and Node 18+.

const te = new TextEncoder();
const td = new TextDecoder();

export function b64encode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function b64decode(str) {
  const bin = atob(String(str).replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function randomHex(bytes) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  let out = '';
  for (const x of b) out += x.toString(16).padStart(2, '0');
  return out;
}

export async function sha256hex(s) {
  const digest = await crypto.subtle.digest('SHA-256', te.encode(String(s)));
  let out = '';
  for (const b of new Uint8Array(digest)) out += b.toString(16).padStart(2, '0');
  return out;
}

// Constant-time comparison of two hex strings (no early exit).
export function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function deriveAesKey(secret) {
  const digest = await crypto.subtle.digest('SHA-256', te.encode(String(secret)));
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Encrypt a plaintext string with AES-256-GCM (key = SHA-256(secret)).
// Returns "enc:v1:<base64(iv || tag || ciphertext)>".
export async function encryptSecret(plain, secret) {
  const key = await deriveAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(plain));
  const ctBytes = new Uint8Array(ct);
  const out = new Uint8Array(12 + ctBytes.length);
  out.set(iv, 0);
  out.set(ctBytes, 12);
  return 'enc:v1:' + b64encode(out);
}

export async function decryptSecret(blob, secret) {
  const parts = String(blob).split(':');
  if (parts[0] !== 'enc') throw new Error('not an encrypted secret');
  const key = await deriveAesKey(secret);
  const raw = b64decode(parts[2]);
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return td.decode(pt);
}
