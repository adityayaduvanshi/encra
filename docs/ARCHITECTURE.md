# Encra — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Developer's App                       │
│                                                          │
│  ┌──────────────┐   ┌──────────────┐  ┌──────────────┐  │
│  │ useE2EChat   │   │ useE2EFile   │  │ useE2EForm   │  │
│  │ (React hook) │   │ (React hook) │  │ (React hook) │  │
│  └──────┬───────┘   └──────┬───────┘  └──────┬───────┘  │
│         │                  │                  │           │
│         └──────────────────┼──────────────────┘           │
│                            │                              │
│                    ┌───────▼──────┐                       │
│                    │  @encra/core │                       │
│                    │  (crypto)    │                       │
│                    └───────┬──────┘                       │
│                            │                              │
│                    ┌───────▼──────┐                       │
│                    │   IndexedDB  │  ← key pairs,         │
│                    │  (idb lib)   │    ratchet state,     │
│                    └──────────────┘    messages           │
└──────────────────────────┬──────────────────────────────┘
                           │ HTTPS / WSS
                           │ Authorization: Bearer {apiKey}
                ┌──────────▼───────────┐
                │    @encra/server     │
                │                      │
                │  POST /v1/keys       │  ← registers publicKey + deviceId
                │  GET  /v1/keys/:uid  │  ← returns all device keys
                │  GET  /health        │
                │                      │
                │  WS  /v1/relay       │  ← routes encrypted messages
                │    (per userId:      │    queues for offline recipients
                │     deviceId)        │
                └──────────┬───────────┘
                           │
                  ┌────────▼────────┐
                  │   PostgreSQL     │
                  │                  │
                  │  public_keys     │  ← user_id, device_id, public_key
                  │  message_queue   │  ← ciphertext blobs only
                  └──────────────────┘
```

---

## Key Registration Flow

```
Alice's browser                      Encra Server              PostgreSQL
      │                                    │                         │
      │  1. generateKeyPair()              │                         │
      │     → { publicKey, privateKey }    │                         │
      │     privateKey → IndexedDB         │                         │
      │                                    │                         │
      │  2. getOrCreateDeviceId()          │                         │
      │     → "abc-123-uuid" → IndexedDB   │                         │
      │                                    │                         │
      │  3. POST /v1/keys                  │                         │
      │     { userId, publicKey, deviceId }├────────────────────────►│
      │     Authorization: Bearer apiKey   │  INSERT public_keys     │
      │◄───────────────────────────────────┤  ON CONFLICT UPDATE     │
      │     201 { userId, deviceId }       │                         │
```

> The server never sees the private key. It only stores the public key.

---

## Message Send Flow (Double Ratchet)

```
Alice                        Server                         Bob
  │                            │                             │
  │  fetchPeerDeviceKeys(bob)   │                             │
  │  GET /v1/keys/bob ─────────►                             │
  │◄──────────────────────────  │                             │
  │  [{ deviceId, publicKey }]  │                             │
  │                             │                             │
  │  For each Bob device:       │                             │
  │  ┌─────────────────────┐    │                             │
  │  │ deriveSharedSecret( │    │                             │
  │  │   alice.privateKey, │    │                             │
  │  │   bob.publicKey     │    │                             │
  │  │ ) → sharedSecret    │    │                             │
  │  │                     │    │                             │
  │  │ ratchet.encrypt(msg)│    │                             │
  │  │ → { header,         │    │                             │
  │  │     ciphertext,     │    │                             │
  │  │     nonce }         │    │                             │
  │  └─────────────────────┘    │                             │
  │                             │                             │
  │  WS: send message ─────────►│                             │
  │  { to: bob,                 │  route to bob:deviceId ────►│
  │    toDeviceId,              │  (or queue if offline)      │
  │    ciphertext, nonce,       │                             │
  │    header }                 │                             │
  │                             │◄──── WS: message ──────────│
  │                             │  { from: alice,             │
  │                             │    fromDeviceId,            │
  │                             │    ciphertext, nonce,       │
  │                             │    header }                 │
  │                             │                             │
  │                             │  ratchet.decrypt(msg)       │
  │                             │  → plaintext                │
  │                             │                             │
  │                             │  saveRatchet → IndexedDB    │
```

The server only sees `{ from, to, ciphertext, nonce, header }`. The `header` contains
only the DH public key for the ratchet step (also encrypted in a real deployment).
The server never sees the plaintext, the shared secret, or the message key.

---

## Multi-Device Architecture

Each browser/device gets a **stable UUID** (`deviceId`) stored in IndexedDB. When a
user logs in on a new device, it registers a new public key under the same `userId`
but a different `deviceId`.

```
Bob's devices:
  public_keys table:
  ┌──────────┬────────────────────┬──────────────┐
  │ user_id  │ device_id          │ public_key   │
  ├──────────┼────────────────────┼──────────────┤
  │ bob      │ a1b2-c3d4 (laptop) │ base64...    │
  │ bob      │ e5f6-g7h8 (phone)  │ base64...    │
  └──────────┴────────────────────┴──────────────┘

When Alice sends to Bob:
  - Fetches both devices from GET /v1/keys/bob
  - Encrypts separately for each device (independent shared secrets)
  - Sends two WS messages: one to bob:a1b2-c3d4, one to bob:e5f6-g7h8
```

---

## Offline Message Queue

When a recipient device is not connected, the relay queues the message in PostgreSQL:

```sql
-- message_queue schema (after migrations 001-003)
id                  BIGSERIAL PRIMARY KEY
recipient_id        TEXT      -- userId
recipient_device_id TEXT      -- deviceId
sender_id           TEXT      -- userId
sender_device_id    TEXT      -- deviceId
ciphertext          TEXT      -- base64
nonce               TEXT      -- base64
header              JSONB     -- ratchet header (opaque, forwarded as-is)
sender_name         TEXT      -- optional display name
created_at          TIMESTAMPTZ
```

On reconnect, `flushQueuedMessages()` delivers all queued messages atomically via
`DELETE ... RETURNING` (prevents double-delivery).

---

## Ratchet State Persistence (IndexedDB)

```
IndexedDB: encra-v1 (version 3)
├── keypairs  { key: userId, value: { pub, priv } }
├── ratchets  { key: "userId:s:peerId:deviceId",   value: RatchetStateExport }
│             { key: "userId:r:peerId:deviceId",   value: RatchetStateExport }
├── messages  { key: userId, value: StoredMessage[] }
└── devices   { key: userId, value: deviceId (UUID) }
```

Ratchet keys are namespaced:
- `s:peerId:deviceId` — **sender** ratchet (Alice's state for sending to Bob's device)
- `r:peerId:deviceId` — **receiver** ratchet (Alice's state for receiving from Bob's device)

State is saved after every `encrypt()` and `decrypt()` call so conversations survive
page reloads and tab closes.

---

## JWT Authentication

The developer's `apiKey` (issued by `encra.dev`) is a JWT signed with `JWT_SECRET`.
Payload: `{ developerId: string }`.

- HTTP routes: validated via `Authorization: Bearer {apiKey}` header
- WebSocket: validated via `?token={apiKey}` query param on upgrade

The JWT does **not** authenticate individual users — user identity is self-asserted
in the `userId` field. Security comes from the cryptographic key binding: you can
only decrypt messages sent to your public key, regardless of what `userId` you claim.

---

## Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | XSalsa20-Poly1305 symmetric encryption |
| Authentication | Poly1305 MAC (built into secretbox) |
| Key agreement | X25519 ECDH (Curve25519) |
| Forward secrecy | Double Ratchet — message keys deleted after use |
| Break-in recovery | DH ratchet step on direction flip → new root key |
| Out-of-order delivery | Skip-key store (up to MAX_SKIP=1000 keys) |
| Multi-device | Independent ratchet per sender→recipient device pair |
| Server zero-knowledge | Server stores only public keys + ciphertext |

---

## Database Migrations

Run in order against PostgreSQL:
```bash
psql $DATABASE_URL -f packages/server/migrations/001_init.sql
psql $DATABASE_URL -f packages/server/migrations/002_message_queue_header.sql
psql $DATABASE_URL -f packages/server/migrations/003_device_keys.sql
```

> **Note on 003**: The `DROP CONSTRAINT IF EXISTS public_keys_pkey` in 003 may silently
> no-op if the constraint has a generated name. If you get `infer_arbiter_indexes` errors,
> run this manually in your SQL editor:
> ```sql
> DO $$ DECLARE r RECORD;
> BEGIN
>   SELECT conname INTO r FROM pg_constraint
>   WHERE conrelid = 'public_keys'::regclass AND contype = 'p';
>   IF FOUND THEN EXECUTE format('ALTER TABLE public_keys DROP CONSTRAINT %I', r.conname); END IF;
> END $$;
> ALTER TABLE public_keys ADD PRIMARY KEY (user_id, device_id);
> ```
