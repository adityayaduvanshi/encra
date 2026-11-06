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

## What this exercises

- X3DH session setup (prekey publish + bundle fetch + 3/4-DH handshake)
- Header-encrypted Double Ratchet message encryption
- Offline queue + flush on (re)connect
- Per-sender inbound serialization, safety numbers, auth/reconnect handling

> ⚠️ The mock relay (`mock-relay.ts`) is for local demos only. It has **no auth**
> and stores everything in process memory. Use `@encra/server` for anything real.
