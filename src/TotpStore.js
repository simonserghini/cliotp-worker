// TotpStore — a single Durable Object holding all entries and API keys.
// A singleton instance serializes requests, which makes HOTP counter advances
// atomic. Secrets are stored AES-256-GCM encrypted (key derived from SECRET).
//
// Plain-class DO form (no `cloudflare:workers` import) so the exact same file
// runs in the Workers runtime and under Node's test runner with a fake ctx.

import {
  hotp, totp, steam, secondsRemaining,
  base32Decode, normalizeSecret, normalizeAlgorithm,
  parseOtpauth, encodeOtpauth, parseMigration,
} from './otp.js';
import {
  sha256hex, timingSafeEqualHex, randomHex, encryptSecret, decryptSecret,
} from './crypto.js';

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function json(obj, status = 200, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

const label = (e) => (e.issuer ? `${e.issuer}: ${e.name}` : e.name);

const nextId = (entries) => entries.reduce((m, e) => Math.max(m, e.id), 0) + 1;

function buildEntry(input) {
  const name = String(input.name || '').trim();
  if (!name) throw new HttpError(400, 'name is required');
  const secret = normalizeSecret(input.secret || '');
  if (!secret) throw new HttpError(400, 'secret is required');
  try { base32Decode(secret); } catch { throw new HttpError(400, 'invalid base32 secret'); }

  const kind = String(input.kind || 'totp').toLowerCase();
  if (!['totp', 'hotp', 'steam'].includes(kind)) throw new HttpError(400, 'kind must be totp, hotp, or steam');
  let digits = Number(input.digits ?? 6);
  let period = Number(input.period ?? 30);
  if (kind === 'steam') { digits = 5; period = 30; }
  if (kind !== 'steam' && digits !== 6 && digits !== 8) throw new HttpError(400, 'digits must be 6 or 8');
  const algorithm = normalizeAlgorithm(input.algorithm || 'SHA1');
  const counter = kind === 'hotp' ? Number(input.counter ?? 0) : 0;
  return { id: 0, name, issuer: String(input.issuer || '').trim(), secret, digits, period, algorithm, kind, counter };
}

function applyEdit(entry, patch) {
  const allowed = ['name', 'issuer', 'secret', 'digits', 'period', 'algorithm', 'kind', 'counter'];
  const merged = { ...entry };
  for (const k of allowed) if (k in patch && patch[k] !== undefined) merged[k] = patch[k];
  const fresh = buildEntry({
    name: merged.name, secret: merged.secret, issuer: merged.issuer,
    digits: merged.digits, period: merged.period, algorithm: merged.algorithm,
    kind: merged.kind, counter: merged.counter,
  });
  fresh.id = entry.id;
  return fresh;
}

const hasDuplicate = (entries, entry) => {
  const lbl = label(entry).toLowerCase();
  return entries.some((e) => label(e).toLowerCase() === lbl);
};

const publicEntry = (e) => ({
  id: e.id, name: e.name, issuer: e.issuer, digits: e.digits, period: e.period,
  algorithm: e.algorithm, kind: e.kind, counter: e.kind === 'hotp' ? e.counter : undefined,
});

const publicKey = (k) => ({ id: k.id, name: k.name, scope: k.scope || 'admin', createdAt: k.createdAt, lastUsedAt: k.lastUsedAt || null });

export class TotpStore {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  // --- storage accessors (secret field is encrypted at rest) ---
  async loadEntries() {
    const arr = (await this.ctx.storage.get('entries')) || [];
    return Promise.all(arr.map(async (e) => ({ ...e, secret: await decryptSecret(e.secret, this.env.SECRET) })));
  }

  async saveEntries(entries) {
    const enc = await Promise.all(entries.map(async (e) => ({ ...e, secret: await encryptSecret(e.secret, this.env.SECRET) })));
    await this.ctx.storage.put('entries', enc);
  }

  async loadKeys() {
    return (await this.ctx.storage.get('keys')) || [];
  }

  async saveKeys(keys) {
    await this.ctx.storage.put('keys', keys);
  }

  // Seed a "default" admin key from API_TOKEN on first access.
  async ensureKeys() {
    const keys = await this.loadKeys();
    if (keys.length === 0 && this.env.API_TOKEN) {
      keys.push({
        id: 'k_' + randomHex(6), name: 'default', scope: 'admin',
        keyHash: await sha256hex(this.env.API_TOKEN),
        createdAt: Math.floor(Date.now() / 1000), lastUsedAt: null,
      });
      await this.saveKeys(keys);
    }
    return keys;
  }

  async authenticate(provided) {
    if (!provided) return { ok: false, key: null };
    if (this.env.API_TOKEN && timingSafeEqualHex(await sha256hex(provided), await sha256hex(this.env.API_TOKEN))) {
      return { ok: true, key: null };
    }
    const h = await sha256hex(provided);
    const key = (await this.loadKeys()).find((k) => timingSafeEqualHex(k.keyHash, h));
    return { ok: Boolean(key), key: key || null };
  }

  async touchLastUsed(key) {
    if (!key || !key.id) return;
    key.lastUsedAt = Math.floor(Date.now() / 1000);
    const keys = await this.loadKeys();
    const k = keys.find((x) => x.id === key.id);
    if (k) { k.lastUsedAt = key.lastUsedAt; await this.saveKeys(keys); }
  }

  async generateCode(entry, now = Math.floor(Date.now() / 1000)) {
    if (entry.kind === 'totp') {
      return { code: await totp(entry.secret, now, entry.period, entry.digits, entry.algorithm), secondsRemaining: secondsRemaining(entry.period, now) };
    }
    if (entry.kind === 'steam') {
      return { code: await steam(entry.secret, now), secondsRemaining: secondsRemaining(30, now) };
    }
    if (entry.kind === 'hotp') {
      return { code: await hotp(entry.secret, entry.counter ?? 0, entry.digits, entry.algorithm), counter: entry.counter ?? 0 };
    }
    throw new HttpError(400, `unknown kind "${entry.kind}"`);
  }

  resolveEntry(entries, ref) {
    if (/^\d+$/.test(ref)) {
      const n = Number(ref);
      const byId = entries.find((e) => e.id === n);
      if (byId) return byId;
      if (n >= 1 && n <= entries.length) return entries[n - 1];
      throw new HttpError(404, `no entry with id/index ${ref}`);
    }
    const needle = ref.toLowerCase();
    const matches = entries.filter((e) => label(e).toLowerCase().includes(needle));
    if (matches.length === 1) return matches[0];
    if (matches.length === 0) throw new HttpError(404, `no entry matches "${ref}"`);
    throw new HttpError(409, `"${ref}" is ambiguous: ${matches.map(label).join(', ')}`);
  }

  async fetch(request) {
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, '') || '/';

    try {
      await this.ensureKeys();

      const sessionEmail = request.headers.get('X-Auth-Email') || '';
      const auth = request.headers.get('Authorization') || '';
      const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      const provided = bearer || request.headers.get('X-Api-Token') || '';
      const cred = sessionEmail ? { ok: true, key: null } : await this.authenticate(provided);
      if (!cred.ok) {
        return json({ error: 'unauthorized' }, 401, { 'WWW-Authenticate': 'Bearer' });
      }
      if (cred.key) await this.touchLastUsed(cred.key);
      const isAdmin = sessionEmail ? true : (!cred.key || cred.key.scope !== 'readonly');

      if (request.method === 'GET' && p === '/api/entries') {
        return json((await this.loadEntries()).map(publicEntry));
      }

      if (request.method === 'POST' && p === '/api/entries') {
        if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
        const body = await request.json().catch(() => ({}));
        const entries = await this.loadEntries();
        let added;
        if (body.uri) {
          const u = String(body.uri);
          if (/^otpauth-migration:\/\//i.test(u)) {
            added = parseMigration(u);
            for (const e of added) { e.id = nextId(entries); entries.push(e); }
          } else {
            const e = parseOtpauth(u);
            if (hasDuplicate(entries, e)) throw new HttpError(409, `"${label(e)}" already exists`);
            e.id = nextId(entries); entries.push(e); added = [e];
          }
        } else {
          const e = buildEntry(body);
          if (hasDuplicate(entries, e)) throw new HttpError(409, `"${label(e)}" already exists`);
          e.id = nextId(entries); entries.push(e); added = [e];
        }
        await this.saveEntries(entries);
        return json(added.map(publicEntry), 201);
      }

      if (request.method === 'GET' && p === '/api/export') {
        if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
        return json({ entries: (await this.loadEntries()).map(encodeOtpauth) });
      }

      if (request.method === 'GET' && p === '/api/codes') {
        const now = Math.floor(Date.now() / 1000);
        const entries = await this.loadEntries();
        const codes = [];
        for (const e of entries) {
          codes.push({ id: e.id, name: e.name, issuer: e.issuer, kind: e.kind, digits: e.digits, period: e.period, algorithm: e.algorithm, ...(await this.generateCode(e, now)) });
        }
        return json(codes);
      }

      if (request.method === 'GET' && p === '/api/keys') {
        if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
        return json((await this.loadKeys()).map(publicKey));
      }

      if (request.method === 'POST' && p === '/api/keys') {
        if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
        const body = await request.json().catch(() => ({}));
        const keys = await this.loadKeys();
        const secret = randomHex(32);
        const key = {
          id: 'k_' + randomHex(6),
          name: String(body.name || '').trim() || 'key-' + (keys.length + 1),
          scope: body.scope === 'readonly' ? 'readonly' : 'admin',
          keyHash: await sha256hex(secret),
          createdAt: Math.floor(Date.now() / 1000),
        };
        keys.push(key);
        await this.saveKeys(keys);
        return json({ id: key.id, name: key.name, scope: key.scope, createdAt: key.createdAt, key: secret }, 201);
      }

      const keyMatch = p.match(/^\/api\/keys\/([^/]+)$/);
      if (keyMatch && request.method === 'DELETE') {
        if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
        const keys = await this.loadKeys();
        if (keys.length <= 1) return json({ error: 'cannot revoke the last API key' }, 400);
        const id = decodeURIComponent(keyMatch[1]);
        const idx = keys.findIndex((k) => k.id === id);
        if (idx < 0) return json({ error: 'no such API key' }, 404);
        keys.splice(idx, 1);
        await this.saveKeys(keys);
        return json({ revoked: id });
      }

      const entryMatch = p.match(/^\/api\/entries\/([^/]+)(?:\/(code|uri))?$/);
      if (entryMatch) {
        const ref = decodeURIComponent(entryMatch[1]);
        const sub = entryMatch[2];

        if (sub === 'code') {
          if (request.method !== 'GET') throw new HttpError(405, 'method not allowed');
          const entries = await this.loadEntries();
          const entry = this.resolveEntry(entries, ref);
          const gen = await this.generateCode(entry);
          if (entry.kind === 'hotp') {
            entry.counter = (entry.counter ?? 0) + 1;
            await this.saveEntries(entries);
          }
          return json({ id: entry.id, name: entry.name, issuer: entry.issuer, kind: entry.kind, ...gen });
        }

        if (sub === 'uri') {
          if (request.method !== 'GET') throw new HttpError(405, 'method not allowed');
          if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
          const entry = this.resolveEntry(await this.loadEntries(), ref);
          return json({ uri: encodeOtpauth(entry) });
        }

        if (request.method === 'GET') {
          return json(publicEntry(this.resolveEntry(await this.loadEntries(), ref)));
        }

        if (request.method === 'DELETE') {
          if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
          const entries = await this.loadEntries();
          const entry = this.resolveEntry(entries, ref);
          await this.saveEntries(entries.filter((e) => e.id !== entry.id));
          return json({ removed: publicEntry(entry) });
        }

        if (request.method === 'PATCH') {
          if (!isAdmin) return json({ error: 'forbidden: admin scope required' }, 403);
          const body = await request.json().catch(() => ({}));
          const entries = await this.loadEntries();
          const entry = this.resolveEntry(entries, ref);
          const updated = applyEdit(entry, body);
          entries[entries.findIndex((e) => e.id === entry.id)] = updated;
          await this.saveEntries(entries);
          return json(publicEntry(updated));
        }

        throw new HttpError(405, 'method not allowed');
      }

      throw new HttpError(404, 'not found');
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      // eslint-disable-next-line no-console
      console.error(err);
      return json({ error: 'internal server error' }, 500);
    }
  }
}
