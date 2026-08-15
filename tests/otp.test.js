import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as o from '../src/otp.js';
import * as c from '../src/crypto.js';

const S = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
const S256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
const S512 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';

test('RFC 4226 HOTP SHA1 vectors', async () => {
  const expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
  for (let i = 0; i < expected.length; i++) {
    assert.equal(await o.hotp(S, i, 6, 'SHA1'), String(expected[i]), `counter ${i}`);
  }
});

test('RFC 6238 TOTP SHA1 vectors (8 digits, period 30)', async () => {
  const vectors = [
    [59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130'],
  ];
  for (const [t, exp] of vectors) {
    assert.equal(await o.totp(S, t, 30, 8, 'SHA1'), exp, `t=${t}`);
  }
});

test('RFC 6238 TOTP SHA256/SHA512 vectors', async () => {
  assert.equal(await o.totp(S256, 59, 30, 8, 'SHA256'), '46119246');
  assert.equal(await o.totp(S512, 59, 30, 8, 'SHA512'), '90693936');
});

test('Steam Guard code (cross-checked against the reference implementation)', async () => {
  assert.equal(await o.steam('JBSWY3DPEHPK3PXP', 1700000000), '2KM2P');
  const code = await o.steam('JBSWY3DPEHPK3PXP', 1710000000);
  assert.match(code, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
});

test('base32 encode/decode roundtrip', () => {
  for (const len of [1, 2, 5, 9, 16, 20, 32]) {
    const raw = new Uint8Array(len).map((_, i) => (i * 7 + 3) & 0xff);
    assert.deepEqual(o.base32Decode(o.base32Encode(raw)), raw, `len ${len}`);
  }
});

test('otpauth parse + encode roundtrip', () => {
  const uri = 'otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30';
  const e = o.parseOtpauth(uri);
  assert.equal(e.name, 'alice@example.com');
  assert.equal(e.issuer, 'GitHub');
  assert.equal(e.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(e.digits, 6);
  assert.equal(e.period, 30);
  assert.equal(o.encodeOtpauth(e), uri);
});

test('Google Authenticator migration import', () => {
  const mig = 'otpauth-migration://offline?data=CjwKDEhlbGxvId6tvu%2B%2BchIRQWRhbSBzY2hvb2wgdGUucCAgASgBMAJCE2E2M2Q3NTE3ODY2MzYzNTU0MjYQAhgBIAA%3D';
  const entries = o.parseMigration(mig);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'Adam school te.p');
  assert.equal(entries[0].secret, 'JBSWY3DPEHPK3PXPXZZA');
  assert.equal(entries[0].algorithm, 'SHA1');
  assert.equal(entries[0].digits, 6);
  assert.equal(entries[0].kind, 'totp');
});

test('crypto: sha256hex, timing-safe compare, random', async () => {
  assert.match(await c.sha256hex('abc'), /^[0-9a-f]{64}$/);
  assert.equal(c.timingSafeEqualHex(await c.sha256hex('abc'), await c.sha256hex('abc')), true);
  assert.equal(c.timingSafeEqualHex(await c.sha256hex('abc'), await c.sha256hex('abd')), false);
  assert.match(c.randomHex(32), /^[0-9a-f]{64}$/);
});

test('crypto: AES-256-GCM roundtrip + tamper detection', async () => {
  const enc = await c.encryptSecret('JBSWY3DPEHPK3PXP', 'secret-key');
  assert.match(enc, /^enc:v1:/);
  assert.equal(await c.decryptSecret(enc, 'secret-key'), 'JBSWY3DPEHPK3PXP');
  await assert.rejects(c.decryptSecret(enc, 'wrong-key'));
});
