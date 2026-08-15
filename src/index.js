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

    if (p === '/') {
      return new Response(
        `cliotp-worker ${VERSION}\n\n` +
        'TOTP/HOTP/Steam over a REST API. Use the cliotpc client:\n\n' +
        '  export CLIOTP_SERVER=https://your-worker.example.com\n' +
        '  export CLIOTP_TOKEN=<your API key>\n' +
        '  cliotpc list\n',
        { headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
      );
    }

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
