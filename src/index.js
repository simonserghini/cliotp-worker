// cliotp-worker — TOTP / HOTP / Steam Guard on Cloudflare Workers.
// Thin router: serves / and /healthz directly, forwards /api/* to the
// singleton Durable Object (which handles auth + storage).
import { TotpStore } from './TotpStore.js';

export { TotpStore };

const VERSION = '0.1.0';
const STORE_NAME = 'global';

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, '') || '/';

    if (p === '/healthz') {
      return json({ ok: true, version: VERSION });
    }

    // `/`, `/app.js`, `/style.css` are served from the `assets` directory
    // (public/) automatically; the Worker only handles non-asset paths.

    if (p.startsWith('/api/')) {
      if (!env.STORE) return json({ error: 'STORE Durable Object binding is missing' }, 500);
      if (!env.API_TOKEN || !env.SECRET) {
        return json({ error: 'set the API_TOKEN and SECRET secrets (wrangler secret put ...)' }, 500);
      }
      const stub = env.STORE.get(env.STORE.idFromName(STORE_NAME));
      return stub.fetch(request);
    }

    return json({ error: 'not found' }, 404);
  },
};
