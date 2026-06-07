# @encra/server

[![license](https://img.shields.io/badge/license-BUSL%201.1-orange)](./LICENSE)

**The Encra key server and WebSocket relay** — the zero-knowledge backend behind [`@encra/react`](https://www.npmjs.com/package/@encra/react) and [`@encra/client`](https://www.npmjs.com/package/@encra/client).

Part of [**Encra**](https://encra.dev) — *"Stripe for end-to-end encryption."* Most developers use the managed server at `api.encra.dev`. This package is for **self-hosting**.

## The golden rule

The server stores only:
1. `user_id + device_id → public_key` mappings (and X3DH prekey bundles)
2. Encrypted ciphertext blobs (offline queue)
3. Timestamps and routing metadata

It **never** sees private keys, plaintext messages, or shared secrets.

## What it does

- **Key + prekey API** — `POST/GET /v1/keys`, `POST/GET /v1/prekeys` (X3DH bundles, atomic one-time-prekey consumption, non-consuming fetch for presence).
- **WebSocket relay** (`/v1/relay`) — first-message JWT auth, routes by `userId:deviceId`, queues messages for offline recipients in PostgreSQL and flushes on reconnect. Routes ephemeral presence frames (never queued).
- **Production hardening** — pino structured logging, helmet security headers, rate limiting, connection caps, WebSocket heartbeats, graceful shutdown.
- **Horizontal scaling** — optional Redis pub/sub for cross-instance delivery and presence (single-instance fallback when `REDIS_URL` is unset).

## Self-host

```bash
git clone https://github.com/adityayaduvanshi/encra
cd encra && npm install

cp packages/server/.env.example packages/server/.env   # set DATABASE_URL + JWT_SECRET

# Run migrations in order (001 → 005)
for f in packages/server/migrations/*.sql; do psql "$DATABASE_URL" -f "$f"; done

npm run build --workspace=packages/server
npm start     --workspace=packages/server
```

### Environment

| Var | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `JWT_SECRET` | ✅ | HS256 secret for developer API-key verification |
| `REDIS_URL` | — | Enables multi-instance pub/sub + presence |
| `JWT_ISSUER` / `JWT_AUDIENCE` | — | Enforce `iss`/`aud` claims |
| `MAX_WS_CONNECTIONS` | — | Connection cap (default 10 000) |
| `QUEUE_RETENTION_DAYS` | — | Offline-queue retention (default 7) |

Node.js 18+, PostgreSQL, Express, `ws`.

## License

**Business Source License 1.1** — self-hosting is permitted for non-commercial use; converts to Apache-2.0 on 2030-01-01. Commercial licenses: [legal@encra.dev](mailto:legal@encra.dev). See [`LICENSE`](./LICENSE).
