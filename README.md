# cliotp-worker

**TOTP / HOTP / Steam Guard codes, served from a Cloudflare Worker.**

The serverless sibling of the `cliotp` bash script and
[`cliotp-server`](https://github.com/simonserghini/cliotp-server) — same crypto,
same REST API, same `cliotpc` CLI. Instead of a VPS, the secrets live in a
**Durable Object** on Cloudflare's edge.

Runs on Workers + Durable Objects (SQLite-backed). Zero runtime dependencies
(WebCrypto only). The existing `cliotpc` terminal client talks to it unchanged,
and the same web UI is served at `/`.

```
$ export CLIOTP_SERVER=https://cliotp.yourname.workers.dev
$ export CLIOTP_TOKEN=<your API key>
$ cliotpc code github
022863
```

---

## Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/simonserghini/cliotp-worker)

> One-click deploy clones this repo to your account and builds it. Set the
> `API_TOKEN` and `SECRET` secrets right after — until then the Worker returns
> a 500.

```sh
npm install            # pulls in wrangler (dev dependency)
npx wrangler secret put API_TOKEN   # paste your admin API key (openssl rand -hex 32)
npx wrangler secret put SECRET      # encryption secret for secrets-at-rest
npx wrangler deploy
```

- **`API_TOKEN`** — the admin/rescue API key. It's always accepted and is
  seeded as the `default` key on first use. Save it somewhere safe.
- **`SECRET`** — used to derive the AES-256-GCM key that encrypts every secret
  before it's written to storage. **Do not change it after adding entries**,
  or the stored secrets become undecryptable.

Local dev: `npm run dev` (bindings are simulated locally by default).

---

## Client

Exactly the same `cliotpc` client from `cliotp-server`:

```sh
cliotpc list
cliotpc code alice
cliotpc code 1 -c
cliotpc add alice --secret JBSWY3DPEHPK3PXP --issuer GitHub
cliotpc add "otpauth://totp/GitHub:alice?secret=...&issuer=GitHub"
cliotpc edit alice --issuer Work
cliotpc rm alice
cliotpc export
```

Set `CLIOTP_SERVER` to your Worker URL and `CLIOTP_TOKEN` to an API key. The
client lives at `../cliotp-server/client.js`.

---

## API

Identical surface to `cliotp-server`:

| Method | Path | Description |
| --- | --- | --- |
| GET | `/healthz` | Liveness (no auth) |
| GET | `/api/entries` | List entries (no secrets) |
| POST | `/api/entries` | Add from fields or `{ "uri": "otpauth://…" }` |
| GET | `/api/entries/:id` | Entry details |
| GET | `/api/entries/:id/code` | Current code (advances HOTP counter) |
| PATCH | `/api/entries/:id` | Edit fields |
| DELETE | `/api/entries/:id` | Remove |
| GET | `/api/entries/:id/uri` | otpauth URI (admin) |
| GET | `/api/codes` | All codes (peek; no HOTP advance) |
| GET | `/api/export` | All otpauth URIs (admin) |
| GET | `/api/keys` | List keys — id/name/scope/lastUsedAt (admin) |
| POST | `/api/keys` | Create a key (`scope`: `admin` or `readonly`) |
| DELETE | `/api/keys/:id` | Revoke a key (never the last) |

Every `/api/*` route requires `Authorization: Bearer <key>` (or
`X-Api-Token`). Key **scopes**: `admin` (default) or `readonly` (fetch codes
only). Duplicate labels are rejected with `409`.

---

## How it works

- A single **Durable Object** (`TotpStore`, instance `global`) holds all
  entries and API keys. Durable Objects serialize requests per instance, which
  makes HOTP counter advances atomic — no distributed race.
- **SQLite-backed** storage (`new_sqlite_classes` migration — new KV-backed
  DO namespaces are no longer allowed on Cloudflare).
- Secrets are stored **AES-256-GCM encrypted** (key = SHA-256(`SECRET`)).
  API keys are stored as **sha256 hashes** only.
- Crypto is WebCrypto (`crypto.subtle`) + a small base32 implementation, so the
  same `src/otp.js` runs in Workers and under Node's test runner unchanged.

### What the Worker version deliberately omits

- **Rate limiting / IP allowlist** — delegated to Cloudflare (WAF rules / rate
  limiting rules in the dashboard), since edge protections sit in front of the
  Worker.
- **`/metrics`** — Cloudflare provides analytics in the dashboard.

---

## Development

```sh
npm test        # node --test (RFC vectors, store lifecycle, scopes, crypto)
```

The suite covers the RFC 4226/6238 vectors, Steam (cross-checked against the
reference implementation), Google migration import, otpauth round-trip,
AES-GCM at-rest encryption, and the full DO API lifecycle (auth, scopes,
HOTP counter atomicity, duplicates, key revocation).

---

## Security notes

- An API key is the whole ballgame: anyone with it can read every code. Use
  strong keys and revoke anything you don't recognize.
- Put Cloudflare **Access** or a WAF rule in front if you want to restrict who
  can reach the Worker at all.
- `SECRET` must stay stable for the life of your stored secrets.

## License

MIT. Go wild.
