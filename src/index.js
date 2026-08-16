// cliotp-worker — TOTP / HOTP / Steam Guard on Cloudflare Workers.
// Routes / and /healthz, serves static assets, handles Google OAuth + sessions,
// and forwards /api/* to the singleton Durable Object.
import { TotpStore } from './TotpStore.js';
import { randomHex, timingSafeEqualHex } from './crypto.js';

export { TotpStore };

const VERSION = '0.2.0';
const STORE_NAME = 'global';
const SESSION_AGE = 30 * 24 * 3600; // 30 days

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

function b64url(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

async function signSession(obj, secret) {
  const payload = b64url(JSON.stringify(obj));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  let hex = '';
  for (const b of new Uint8Array(sig)) hex += b.toString(16).padStart(2, '0');
  return payload + '.' + hex;
}

async function verifySession(token, secret) {
  if (!token || !secret) return null;
  const dot = token.indexOf('.');
  if (dot < 0) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const expected = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  let hex = '';
  for (const b of new Uint8Array(expected)) hex += b.toString(16).padStart(2, '0');
  if (!timingSafeEqualHex(hex, sig)) return null;
  try {
    const obj = JSON.parse(unb64url(payload));
    if (!obj.exp || obj.exp < Date.now() / 1000) return null;
    return obj;
  } catch { return null; }
}

function googleConfig(env) {
  const c = {
    clientId: env.GOOGLE_CLIENT_ID || '',
    clientSecret: env.GOOGLE_CLIENT_SECRET || '',
    redirectUri: env.GOOGLE_REDIRECT_URI || '',
    allowed: (env.GOOGLE_ALLOWED_EMAILS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
    sessionSecret: env.SESSION_SECRET || '',
  };
  c.enabled = Boolean(c.clientId && c.clientSecret && c.allowed.length && c.sessionSecret);
  return c;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, '') || '/';
    const google = googleConfig(env);

    if (p === '/healthz') return json({ ok: true, version: VERSION });

    if (p === '/auth/status') {
      const session = await verifySession(getCookie(request, 'cliotp_session'), google.sessionSecret);
      return json({ authenticated: Boolean(session), googleEnabled: google.enabled, email: session ? session.email : null });
    }

    if (p === '/auth/logout') {
      return json({ ok: true }, 200, { 'Set-Cookie': 'cliotp_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' });
    }

    if (p === '/auth/google/login') {
      if (!google.enabled) return json({ error: 'google auth not configured' }, 404);
      const state = randomHex(16);
      const ru = google.redirectUri || `${url.protocol}//${url.host}/auth/google/callback`;
      const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth'
        + `?client_id=${encodeURIComponent(google.clientId)}`
        + `&redirect_uri=${encodeURIComponent(ru)}`
        + '&response_type=code&scope=' + encodeURIComponent('openid email')
        + `&state=${encodeURIComponent(state)}`;
      return new Response(null, { status: 302, headers: { Location: authUrl, 'Set-Cookie': `cliotp_oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600` } });
    }

    if (p === '/auth/google/callback') {
      if (!google.enabled) return json({ error: 'google auth not configured' }, 404);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state || state !== getCookie(request, 'cliotp_oauth_state')) {
        return json({ error: 'invalid oauth state' }, 400);
      }
      const ru = google.redirectUri || `${url.protocol}//${url.host}/auth/google/callback`;
      let tokens;
      try {
        const tr = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ code, client_id: google.clientId, client_secret: google.clientSecret, redirect_uri: ru, grant_type: 'authorization_code' }),
        });
        tokens = await tr.json();
      } catch { return json({ error: 'token exchange failed' }, 502); }
      if (!tokens.access_token) return json({ error: tokens.error_description || tokens.error || 'token exchange failed' }, 400);
      let info;
      try {
        const ur = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: 'Bearer ' + tokens.access_token } });
        info = await ur.json();
      } catch { return json({ error: 'userinfo request failed' }, 502); }
      const email = String(info.email || '').toLowerCase();
      if (!info.email_verified || !email) return json({ error: 'unverified email' }, 403);
      if (!google.allowed.includes(email)) return json({ error: 'email not allowed' }, 403);
      const session = await signSession({ email, exp: Math.floor(Date.now() / 1000) + SESSION_AGE }, google.sessionSecret);
      const secure = url.protocol === 'https:' ? '; Secure' : '';
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/',
          'Set-Cookie': [
            `cliotp_session=${session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_AGE}${secure}`,
            'cliotp_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
          ],
        },
      });
    }

    if (p.startsWith('/api/')) {
      if (!env.STORE) return json({ error: 'STORE Durable Object binding is missing' }, 500);
      if (!env.SECRET) return json({ error: 'set the SECRET secret (wrangler secret put SECRET)' }, 500);
      const stub = env.STORE.get(env.STORE.idFromName(STORE_NAME));
      const session = await verifySession(getCookie(request, 'cliotp_session'), google.sessionSecret);
      if (session) {
        return stub.fetch(new Request(request, { headers: { 'X-Auth-Email': session.email } }));
      }
      return stub.fetch(request);
    }

    return json({ error: 'not found' }, 404);
  },
};
