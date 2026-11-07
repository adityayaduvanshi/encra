# Encra — Codex Master Prompt

## Project Overview
**Encra** (`@encra/*`) is an npm SDK for adding Signal-level end-to-end encryption
to any app. Think "Stripe for E2E encryption." Developers get an API key, drop in a
hook, and their users get cryptographic privacy without knowing anything about
cryptography.

**Two connected repos:**
- `D:\projects\e2e` — SDK monorepo (this repo, npm packages)
- `D:\projects\web\e2e-chat` — `encra.dev` marketing site + SaaS dashboard (Next.js)

The web app issues API keys to developers; the SDK packages do the actual
encryption. Changes to the public API surface (hooks, types, errors) should be
reflected in the web docs at `D:\projects\web\e2e-chat\app\(marketing)\docs\`.

---

## Core Philosophy
- **Security first** — never cut corners on crypto. If unsure, ask.
- **Developer experience second** — one-line API, great errors, great docs.
- **Zero trust architecture** — the key server must never be able to read messages.
- **No magic** — every function does one thing, is testable, and is explainable.

---

## Tech Stack — Do Not Deviate

### Crypto
- `libsodium-wrappers` for all cryptographic operations
- X25519 (ECDH) for key exchange via `crypto_box_keypair` / `crypto_scalarmult`
- XSalsa20-Poly1305 for message encryption via `crypto_secretbox`
- Keyed BLAKE2b-256 (not HKDF) for KDF/ratchet via `crypto_generichash`
- Never use: MD5, SHA1, ECB mode, `Math.random()` for anything crypto

### Backend (Key Server) — `@encra/server`
- Node.js + Express (not Fastify)
- PostgreSQL via `pg` (no ORM)
- Redis via `ioredis` — optional pub/sub for horizontal scaling + presence TTL keys
- WebSockets via `ws`
- JWT for developer API key auth (not sessions)

### Frontend SDK — `@encra/react`, `@encra/core`, `@encra/client`
- TypeScript strict mode — no `any` types ever
- IndexedDB via `idb` for local key + ratchet state storage
- Works in: Node.js 18+, Chrome, Firefox, Safari, React Native

### Web Dashboard — `D:\projects\web\e2e-chat`
- Next.js 16 + React 19 + Tailwind CSS v4 + shadcn/ui
- Better Auth (email/password + GitHub OAuth)
- PostgreSQL via `pg`, Resend for transactional email
- `@encra/core` used directly in the chat demo page

### Package Structure
```
packages/
├── core/    @encra/core    v0.3.0  → pure crypto, zero server/React deps
├── server/  @encra/server  v0.2.0  → key server + WebSocket relay
├── react/   @encra/react   v0.5.0  → React hooks (useE2EChat, useE2EFile, useE2EForm, useE2EPresence)
├── client/  @encra/client  v0.4.0  → framework-agnostic JS client (EncraClient)
└── cli/     encra          v0.3.0  → npx encra init/keygen/ping
```

---

## What's Built (Accurate as of v0.5.x)

### @encra/core v0.3.0 ✅ Complete
- `generateKeyPair()`, `exportKey()`, `importKey()` — X25519 key pairs
- `deriveSharedSecret()` — ECDH key exchange
- `encrypt()` / `decrypt()` — XSalsa20-Poly1305 with random nonce per call
- `generateFingerprint()` — Signal-style safety numbers (BLAKE2b)
- `DoubleRatchet` class — full Double Ratchet, out-of-order support (MAX_SKIP=1000),
  state export/import, forward secrecy via per-message key deletion
- `encryptField(value, key)` / `decryptField(encrypted, key)` — standalone symmetric
  field encryption; URL-safe base64 output; no server or React required
- `generateFieldKey()` — 32-byte CSPRNG key for field encryption
- Typed errors: `InvalidKeyError`, `DecryptionFailedError`, `KeyNotFoundError`
- `derivePresenceKey()` — BLAKE2b-256 domain-separated (`encra:presence:v1`) symmetric presence
  key from a 32-byte session secret (the X3DH session root key → forward-secret at session granularity)
- `encryptPresence(payload, key)` / `decryptPresence(encrypted, key)` — XSalsa20-Poly1305 for presence
- **114 tests, 99.48% coverage**

### @encra/server v0.2.0 ✅ Production-ready
- `POST /v1/keys` — upsert device public key (`ON CONFLICT (user_id, device_id)`)
- `GET /v1/keys/:userId` — returns all device keys: `{ userId, devices: [{ deviceId, publicKey }] }`
- `GET /health` — DB latency + Redis ping + uptime; returns 503 when DB unreachable
- WebSocket relay `/v1/relay?token={jwt}` — routes by `userId:deviceId`, queues
  offline messages in PostgreSQL, flushes on reconnect
- **Structured logging** — pino JSON (pretty-prints in development, JSON in production)
- **Security headers** — helmet (HSTS, X-Frame-Options, etc.)
- **Rate limiting** — 200 req/min global + 20 reg/min on `POST /v1/keys` (express-rate-limit)
- **PostgreSQL pool** — min:2, max:20, idle/connection/statement timeouts, error handler
- **WebSocket heartbeat** — ping/pong every 30s, 10s pong timeout, auto-terminate dead sockets
- **Registration timeout** — unregistered connections closed after 15s
- **Connection cap** — configurable max connections (MAX_WS_CONNECTIONS, default 10 000)
- **Redis pub/sub** — optional horizontal scaling when REDIS_URL is set; single-instance
  fallback when not set; presence keys track online users across instances
- **Offline queue cleanup** — deletes messages older than QUEUE_RETENTION_DAYS (default 7)
  every 6 hours; interval.unref() so it never blocks process exit
- **Graceful shutdown** — SIGTERM/SIGINT: stops server → drains DB pool → closes Redis
- **Unhandled rejection guard** — logs and does not exit; uncaughtException triggers shutdown
- Presence relay: routes `type: 'presence'` frames synchronously; drops silently for offline recipients (never queued)
- Presence frames (`type: 'presence'`) routed synchronously, never queued
- `GET /v1/prekeys/:userId/:deviceId?consumeOneTime=false` — non-consuming bundle fetch for
  ephemeral presence sessions (3-DH X3DH; doesn't drain the one-time-prekey pool)
- **51 tests, ~90% coverage** (infra adapters excluded: redis.ts, index.ts)

### @encra/react v0.5.0 ✅ Complete
- `useE2EChat` — real-time E2E chat. Ratchet state persisted to IndexedDB.
  Exponential backoff reconnect. Multi-device send.
- `useE2EFile` — encrypt/decrypt `File`/`Blob`. One envelope per recipient device. ≤50 MB.
  ⚠️ Still uses static ECDH (no MITM protection, no forward secrecy) — X3DH upgrade pending.
- `useE2EForm` — encrypt form fields before submission. Per-field unique nonces.
  ⚠️ Still uses static ECDH — X3DH upgrade pending.
- `useE2EPresence` — encrypted presence: online/offline status, typing indicators, last-seen,
  ghost mode. Presence key = `BLAKE2b(X3DH session root, "encra:presence:v1")` — directional
  3-DH X3DH sessions (OTP-free via `consumeOneTime=false`, so they never drain the chat prekey
  pool). Ephemeral (never queued). Ghost mode persisted to IndexedDB.
- `E2EChatProvider` + `useE2EChatConfig()` — context-based config
- All hooks share one IndexedDB key pair per `userId` via `ratchetStore.ts`
- **45 tests, ~90% coverage**

### @encra/client v0.4.0 ✅ Complete
- `EncraClient` — framework-agnostic class with event-emitter interface
- Same multi-device, ratchet persistence, reconnect logic as React hooks
- `sendPresence(to, payload)` / `setGhostMode(enabled)` / `ghostMode` getter / `presence` event —
  session-derived X3DH presence, mirroring `useE2EPresence`
- **29 tests passing, ~89% coverage**

### encra CLI v0.3.0 ✅ Complete
- `encra init` — detects framework (Next/React/RN/Node), writes `.env.example` + starter component
- `encra keygen` — generates X25519 key pair + fingerprint
- `encra ping` — health check + auth verification

### Vite Playground ✅ Complete
- `examples/vite/` — standalone Vite playground for all three hooks
- Debug Inspector dialog showing key exchange, ratchet steps, transport events
- Config persisted to `localStorage`

---

## Architecture

See **`docs/ARCHITECTURE.md`** for system design, key flows, and security model.
See **`docs/CRYPTO.md`** for cryptographic primitives and Double Ratchet details.
See **`docs/HOOKS.md`** for React hook API reference.

### The Golden Rule
The server stores ONLY:
1. `user_id + device_id → public_key` mapping
2. Encrypted ciphertext blobs (offline queue)
3. Timestamps and metadata

The server NEVER sees: private keys, plaintext messages, shared secrets.

---

## Current File Structure

```
packages/core/src/
├── crypto/
│   ├── keyPair.ts        → generateKeyPair, exportKey, importKey, sodiumReady
│   ├── keyExchange.ts    → deriveSharedSecret
│   ├── ratchet.ts        → DoubleRatchet class (392 lines)
│   ├── encrypt.ts        → encrypt, decrypt
│   ├── field.ts          → encryptField, decryptField, generateFieldKey
│   ├── presence.ts       → derivePresenceKey, encryptPresence, decryptPresence
│   └── fingerprint.ts    → generateFingerprint
├── errors.ts             → InvalidKeyError, DecryptionFailedError, KeyNotFoundError
└── index.ts

packages/react/src/
├── useE2EChat.ts         → chat hook (~430 lines)
├── useE2EFile.ts         → file encryption hook
├── useE2EForm.ts         → form field encryption hook
├── useE2EPresence.ts     → encrypted presence hook (~430 lines)
├── ratchetStore.ts       → IndexedDB layer (keypairs, ratchets, messages, devices, settings)
├── E2EChatProvider.tsx   → context wrapper
└── index.ts

packages/client/src/
├── EncraClient.ts        → framework-agnostic client class (presence methods added)
├── ratchetStore.ts       → same IndexedDB layer (keypairs, ratchets, messages, devices, settings)
└── index.ts

packages/server/src/
├── app.ts                → Express app, CORS, route mounts
├── index.ts              → HTTP + WebSocket server start
├── errors.ts             → HttpError, NotFoundError, UnauthorizedError, BadRequestError
├── db/pool.ts            → PostgreSQL pool singleton
├── middleware/auth.ts    → JWT Bearer verification
├── routes/health.ts      → GET /health
├── routes/keys.ts        → POST /v1/keys, GET /v1/keys/:userId
├── routes/prekeys.ts     → POST /v1/prekeys, GET /v1/prekeys/:userId/:deviceId?consumeOneTime=
└── ws/relay.ts           → WebSocket relay + offline queue + presence routing (~250 lines)

packages/server/migrations/
├── 001_init.sql                    → public_keys + message_queue tables
├── 002_message_queue_header.sql    → adds header + sender_name columns
├── 003_device_keys.sql             → multi-device composite PK + device routing
├── 004_prekeys.sql                 → signed_prekeys + one_time_prekeys tables
└── 005_prekeys_identity.sql        → identity_keys table for X3DH bundles

packages/cli/src/
├── commands/init.ts, keygen.ts, ping.ts
├── utils/detect.ts, print.ts, snippets.ts
└── index.ts

examples/vite/            → Standalone Vite playground app
docs/                     → Architecture, crypto, hooks reference docs
```

---

## What to Build Next

1. **File/form X3DH security migration** ← **NEXT PRIORITY**
   - `useE2EFile` + `useE2EForm` + `EncraClient` still use static ECDH (`crypto_box_beforenm`)
   - No MITM protection (no signed-prekey verification), no forward secrecy
   - Fix: per-file ephemeral key + 3-DH X3DH (same model as presence but OTP-free)
   - New core helpers: `deriveFileKey()` / `deriveFileKeyRecipient()` (BLAKE2b, domain `encra:file:v1`)
   - `EncryptedFile` / `EncryptedFields` gain `ephemeralPublicKey`, `senderIdentityKey`, `signedPrekeyId` per device
   - **Do NOT publish `@encra/react` or `@encra/client` until this is done** (HIPAA/GDPR keywords)

2. **Dashboard chat migration** — `D:\projects\web\e2e-chat\app\dashboard\chat` still
   uses manual ratchet code instead of `useE2EChat`

3. **Key deletion endpoint** — `DELETE /v1/keys/:userId/:deviceId` to revoke a device

4. **`encra init` vanilla JS template** — currently only generates React snippets;
   add an `EncraClient` template for non-React projects

5. **Self-device sync** — sent messages should also go to the sender's own other devices
   (small loop change in `useE2EChat` / `EncraClient.sendMessage`)

6. **History backup / recovery code** — encrypted key export with passphrase, recovery flow

7. **Private key at rest** — wrap private key with a WebAuthn/Credential Management
   device-bound key (mentioned in docs/CRYPTO.md Security Considerations)

8. **`useE2EPresence` in Vite playground** — add a presence demo panel to `examples/vite/`

---

## Testing

### Running Tests (per package — do NOT run vitest from repo root)
```bash
cd packages/core   && npm test   # 114 tests, 99.48% coverage
cd packages/react  && npm test   # 45 tests, ~90% coverage
cd packages/client && npm test   # 29 tests, ~89% coverage
cd packages/server && npm test   # 51 tests, ~90% coverage (no real DB/Redis needed)
```

> ⚠️ Running `npx vitest run` from the repo root ignores per-package configs and
> fails with libsodium ESM resolution errors. Always run tests inside each package.

### Server Test Environment
```bash
DATABASE_URL=postgresql://...
JWT_SECRET=any-test-secret
```

### Coverage Targets
| Package | Lines | Branches | Functions |
|---------|-------|----------|-----------|
| core    | 90%   | 90%      | 90%       |
| react   | 85%   | 70%      | 85%       |
| client  | 85%   | 70%      | 85%       |

---

## Code Standards

### Every exported function must have:
- JSDoc with `@param`, `@returns`, `@throws`, `@example`
- Input validation at top (throw typed errors)
- Corresponding unit test

### Error Handling
- Use typed errors: `KeyNotFoundError`, `DecryptionFailedError`, `InvalidKeyError`
- Never swallow errors silently
- Error messages must be actionable

### Naming
- Functions: camelCase, verb-first → `encryptMessage()`, `deriveSharedKey()`
- Types: PascalCase → `EncryptedMessage`, `KeyPair`, `DeviceKey`
- Constants: UPPER_SNAKE → `MAX_SKIP_KEYS`, `PEER_KEY_TTL_MS`, `BACKOFF_MAX_MS`
- Files: camelCase.ts

---

## Public API Quick Reference

```typescript
// @encra/react — React hooks
import { useE2EChat, useE2EFile, useE2EForm, useE2EPresence } from '@encra/react'

const { messages, isReady, isConnecting, sendMessage, error } = useE2EChat({
  apiKey, userId, serverUrl?, onError?, onWireMessage?,
})
const { encryptFile, decryptFile, isReady } = useE2EFile({ apiKey, userId })
const { encryptFields, decryptFields, isReady } = useE2EForm({ apiKey, userId })

const { presence, isReady, ghostMode, setGhostMode, sendTyping, setStatus, error } = useE2EPresence({
  apiKey, userId, contacts: ['bob', 'carol'], serverUrl?, onError?,
})

// @encra/client — framework-agnostic
import { EncraClient } from '@encra/client'
const client = new EncraClient({ apiKey, userId })
await client.connect()
client.on('message',  (msg)   => {})
client.on('presence', (event) => console.log(event.from, event.payload.status))
await client.sendMessage('bob', 'Hello!')
await client.sendPresence('bob', { status: 'online', lastSeenAt: Date.now(), isTyping: false })
await client.setGhostMode(true)   // broadcasts offline, suppresses future presence sends
console.log(client.ghostMode)     // false

// @encra/core — standalone field encryption (no server needed)
import { encryptField, decryptField, generateFieldKey } from '@encra/core'
const key = await generateFieldKey()
const enc = await encryptField('secret', key)   // { ciphertext, nonce }
const val = await decryptField(enc, key)         // 'secret'
```

---

## Security Red Lines — Never Cross These
- Never log private keys, shared secrets, or plaintext messages
- Never use a nonce/IV twice with the same key
- Never store private keys in localStorage (IndexedDB only)
- Never send private keys over the network
- Never use non-constant-time comparison for auth tokens
- Never roll your own crypto primitives — libsodium only

---

## Definition of Done
- [ ] Code written, follows all standards above
- [ ] Tests pass with coverage above threshold
- [ ] JSDoc on every exported function
- [ ] README / docs updated if public API changed
- [ ] No TypeScript errors (strict mode)
- [ ] Tested in browser + Node.js environments
