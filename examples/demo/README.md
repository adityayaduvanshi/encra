# Encra Chat Demo (self-contained, no database)

A two-user end-to-end encrypted chat you can run locally with **one command**. Both
users run a real `EncraClient` (full X3DH handshake + Double Ratchet). The relay is
an in-memory Vite plugin — **no Postgres, no Redis, no JWT** — so you can test the
SDK end to end without any infrastructure.

## Run

From the repo root:

```bash
npm run demo
```

That builds `@encra/core` and `@encra/client`, installs the demo's dev deps, and
starts Vite at **http://localhost:5280**.

(Equivalent manual steps: `npm run build -w @encra/core -w @encra/client`, then
`cd examples/demo && npm install && npm run dev`.)

## What to try

- Type in either pane and hit **Send** — messages flow Alice ↔ Bob, encrypted.
- **Compute safety number** — both sides must show the same 60-digit code. That's
  the man-in-the-middle check (`getSafetyNumber`).
- Open **DevTools → Network → WS** and watch the `/v1/relay` frames: only
  `ciphertext` / `nonce` / `encHeader` cross the wire — never plaintext.
- **Reset demo data** wipes this origin's IndexedDB (keys, ratchets, history) for a
  clean session.

## Persistent history (store in YOUR database)

The Double Ratchet is forward-secret: a message key is deleted the moment the
message is decrypted, so ratchet ciphertext can be decrypted **once** — it's
transport, not storage. To keep history, re-encrypt each message **at rest**
under a per-conversation key that never leaves the client, and persist the
ciphertext in your own database:

```ts
// On each sent/received message — save ciphertext to YOUR DB:
const record = await client.encryptForStorage(message)  // { id, conversationId, timestamp, ciphertext, nonce }
await db.insert('messages', record)                      // id/conversationId/timestamp stay queryable

// On load — fetch a PAGE and decrypt only what you show:
const page = await db.query(
  'SELECT * FROM messages WHERE conversation_id = $1 ORDER BY timestamp DESC LIMIT 50', [peerId])
const messages = await Promise.all(page.map((r) => client.decryptFromStorage(r)))
```

In this demo the mock server also plays the role of "your database" at
`/app/messages` (POST to save, GET to page). Every message is saved there, the
**Reload from DB** button re-renders a pane purely from those encrypted records,
and **↑ Load older** pages back through history (page size 5). Because each record
is independently encrypted, decryption is random-access — a long conversation is
a pagination problem, not a crypto one.

## What this exercises

- X3DH session setup (prekey publish + bundle fetch + 3/4-DH handshake)
- Header-encrypted Double Ratchet message encryption
- Offline queue + flush on (re)connect
- Per-sender inbound serialization, safety numbers, auth/reconnect handling
- Message ids + conversations, and at-rest history (`encryptForStorage` / `decryptFromStorage`)

> ⚠️ The mock relay (`mock-relay.ts`) is for local demos only. It has **no auth**
> and stores everything in process memory. Use `@encra/server` for anything real.
