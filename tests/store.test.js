import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TotpStore } from '../src/TotpStore.js';

const S = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"

function makeCtx() {
  const mem = new Map();
  return {
    mem,
    storage: {
      get: async (k) => (mem.has(k) ? structuredClone(mem.get(k)) : undefined),
      put: async (k, v) => { mem.set(k, structuredClone(v)); },
      delete: async (k) => { mem.delete(k); },
    },
    blockConcurrencyWhile: async (fn) => fn(),
    waitUntil: () => {},
  };
}

function makeStore() {
  const ctx = makeCtx();
  const env = { API_TOKEN: 'root-token', SECRET: 'enc-secret' };
  return { store: new TotpStore(ctx, env), ctx };
}

async function req(store, method, path, { token = 'root-token', body, email } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (email) headers['X-Auth-Email'] = email;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await store.fetch(new Request('http://x' + path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  }));
  const text = await res.text();
  let j = null;
  try { j = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { status: res.status, body: j };
}

test('auth is required', async () => {
  const { store } = makeStore();
  assert.equal((await req(store, 'GET', '/api/entries', { token: null })).status, 401);
  assert.equal((await req(store, 'GET', '/api/entries', { token: 'wrong' })).status, 401);
  assert.equal((await req(store, 'GET', '/api/entries')).status, 200);
});

test('full entry lifecycle with deterministic HOTP codes', async () => {
  const { store, ctx } = makeStore();

  const created = await req(store, 'POST', '/api/entries', {
    body: { name: 'rfc', secret: S, kind: 'hotp', digits: 6, algorithm: 'SHA1', counter: 0 },
  });
  assert.equal(created.status, 201);
  const id = created.body[0].id;

  // peek does not advance the counter
  const peek1 = await req(store, 'GET', '/api/codes');
  assert.equal(peek1.body.find((e) => e.id === id).code, '755224');
  const peek2 = await req(store, 'GET', '/api/codes');
  assert.equal(peek2.body.find((e) => e.id === id).code, '755224');

  // consuming advances it
  const consumed = await req(store, 'GET', `/api/entries/${id}/code`);
  assert.equal(consumed.body.code, '755224');
  const peek3 = await req(store, 'GET', '/api/codes');
  assert.equal(peek3.body.find((e) => e.id === id).code, '287082');

  // secret is encrypted at rest
  const stored = JSON.stringify(ctx.mem.get('entries'));
  assert.ok(!stored.includes(S), 'secret must not appear in plaintext at rest');

  // list never leaks the secret
  const list = await req(store, 'GET', '/api/entries');
  assert.equal(list.body.find((e) => e.id === id).secret, undefined);

  // edit
  const edited = await req(store, 'PATCH', `/api/entries/${id}`, { body: { name: 'renamed' } });
  assert.equal(edited.status, 200);
  assert.equal(edited.body.name, 'renamed');

  // delete
  assert.equal((await req(store, 'DELETE', `/api/entries/${id}`)).status, 200);
  assert.equal((await req(store, 'GET', '/api/entries')).body.length, 0);
});

test('scopes, lastUsedAt, and duplicate detection', async () => {
  const { store } = makeStore();

  // bootstrap default key exists and never exposes secrets/hashes
  const keys = await req(store, 'GET', '/api/keys');
  assert.equal(keys.status, 200);
  assert.ok(keys.body.some((k) => k.name === 'default'));
  assert.equal(keys.body[0].keyHash, undefined);

  // create a readonly key
  const ro = await req(store, 'POST', '/api/keys', { body: { name: 'ro', scope: 'readonly' } });
  assert.equal(ro.status, 201);
  assert.equal(ro.body.scope, 'readonly');
  const roKey = ro.body.key;

  // readonly can read codes but not mutate/export/manage keys
  assert.equal((await req(store, 'GET', '/api/codes', { token: roKey })).status, 200);
  assert.equal((await req(store, 'POST', '/api/entries', { token: roKey, body: { name: 'x', secret: 'JBSWY3DPEHPK3PXP' } })).status, 403);
  assert.equal((await req(store, 'GET', '/api/export', { token: roKey })).status, 403);
  assert.equal((await req(store, 'GET', '/api/keys', { token: roKey })).status, 403);

  // lastUsedAt is recorded after use
  await req(store, 'GET', '/api/codes', { token: roKey });
  const keysAfter = await req(store, 'GET', '/api/keys');
  assert.ok(keysAfter.body.find((k) => k.id === ro.body.id).lastUsedAt != null);

  // duplicate labels rejected
  const add1 = await req(store, 'POST', '/api/entries', { body: { name: 'dup', secret: 'JBSWY3DPEHPK3PXP', issuer: 'X' } });
  assert.equal(add1.status, 201);
  assert.equal((await req(store, 'POST', '/api/entries', { body: { name: 'dup', secret: 'JBSWY3DPEHPK3PXP', issuer: 'X' } })).status, 409);

  // revoking works and is not allowed on the last key
  assert.equal((await req(store, 'DELETE', `/api/keys/${ro.body.id}`)).status, 200);
  const remaining = (await req(store, 'GET', '/api/keys')).body;
  assert.equal(remaining.length, 1);
  assert.equal((await req(store, 'DELETE', `/api/keys/${remaining[0].id}`)).status, 400);
});

test('session (X-Auth-Email) grants admin access', async () => {
  const { store } = makeStore();
  // no API key, but a session email header from the worker → admin
  const keys = await req(store, 'GET', '/api/keys', { token: null, email: 'me@example.com' });
  assert.equal(keys.status, 200);
  const created = await req(store, 'POST', '/api/keys', { token: null, email: 'me@example.com', body: { name: 'from-session' } });
  assert.equal(created.status, 201);
  // without the header and without a key → still 401
  const noAuth = await req(store, 'GET', '/api/keys', { token: null });
  assert.equal(noAuth.status, 401);
});

test('otpauth URI and migration import', async () => {
  const { store } = makeStore();

  const uri = await req(store, 'POST', '/api/entries', {
    body: { uri: 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30' },
  });
  assert.equal(uri.status, 201);
  assert.equal(uri.body[0].name, 'alice');
  assert.equal(uri.body[0].issuer, 'GitHub');

  const mig = 'otpauth-migration://offline?data=CjwKDEhlbGxvId6tvu%2B%2BchIRQWRhbSBzY2hvb2wgdGUucCAgASgBMAJCE2E2M2Q3NTE3ODY2MzYzNTU0MjYQAhgBIAA%3D';
  const m = await req(store, 'POST', '/api/entries', { body: { uri: mig } });
  assert.equal(m.status, 201);
  assert.equal(m.body[0].name, 'Adam school te.p');
});
