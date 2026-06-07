# @encra/core

[![npm](https://img.shields.io/npm/v/@encra/core?color=22c55e)](https://www.npmjs.com/package/@encra/core)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)

**Signal-grade end-to-end encryption primitives for JavaScript & TypeScript.** Zero framework dependencies, zero server dependencies — just the crypto, built on [libsodium](https://doc.libsodium.org/).

Part of [**Encra**](https://encra.dev) — *"Stripe for end-to-end encryption."* This is the low-level core; most apps use [`@encra/react`](https://www.npmjs.com/package/@encra/react) or [`@encra/client`](https://www.npmjs.com/package/@encra/client) instead.

## Install

```bash
npm install @encra/core
```

Works in Node.js 18+, modern browsers, and React Native. TypeScript types included.

## What's inside

| Area | Primitive |
|---|---|
| Key pairs | X25519 — `generateKeyPair`, `exportKey`, `importKey` |
| Key exchange | ECDH — `deriveSharedSecret` |
| Encryption | XSalsa20-Poly1305 (authenticated) — `encrypt`, `decrypt` |
| Identity keys | Ed25519 — `generateIdentityKeyPair`, `sign`, `verify` |
| Session setup | **X3DH** (signed + one-time prekeys) — `x3dhInitiate`, `x3dhRespond`, `buildPreKeyBundle` |
| Messaging | **Double Ratchet with header encryption** — `DoubleRatchet` |
| Presence | session-derived — `derivePresenceKey`, `encryptPresence`, `decryptPresence` |
| Field/column | standalone symmetric — `encryptField`, `decryptField`, `generateFieldKey` |
| Verification | safety numbers — `generateFingerprint` |

All KDF/ratchet steps use keyed BLAKE2b-256. Every nonce comes from the OS CSPRNG (`randombytes_buf`). No `Math.random`, no homegrown primitives.

## Quick start — field encryption (no server needed)

```ts
import { generateFieldKey, encryptField, decryptField } from '@encra/core'

const key = await generateFieldKey()                    // 32-byte CSPRNG key
const enc = await encryptField('123-45-6789', key)      // { ciphertext, nonce } (base64url)
const ssn = await decryptField(enc, key)                // '123-45-6789'
```

## Quick start — Double Ratchet session (via X3DH)

```ts
import { x3dhInitiate, x3dhRespond, DoubleRatchet } from '@encra/core'

// Alice (initiator) — fetches Bob's published prekey bundle
const init  = await x3dhInitiate(aliceIdentity, bobBundle)   // verifies Bob's signed-prekey signature
const alice = await DoubleRatchet.initSender(init.sessionKeys, init.signedPreKeyPublic)
const msg   = await alice.encrypt('Hello Bob')               // { encHeader, ciphertext, nonce }

// Bob (responder)
const keys = await x3dhRespond(bobIdentity, bobSpk, bobOtp, init.message)
const bob  = await DoubleRatchet.initReceiver(keys, bobSpkKeyPair)
const text = await bob.decrypt(msg)                          // 'Hello Bob'
```

Ratchet state serializes via `ratchet.export()` / `DoubleRatchet.fromExport()` for persistence (store in IndexedDB, never `localStorage`).

## Security model

- **Forward secrecy** — per-message keys are deleted immediately after use.
- **Break-in recovery** — a DH ratchet step on every direction change.
- **Header encryption** — the ratchet public key and counters never travel in plaintext.
- **Authenticated handshake** — X3DH verifies the signed-prekey signature, defeating a key-substituting server.

> Confirm a peer's identity out of band with `generateFingerprint()` (Trust On First Use).

## Docs & license

Full docs at [encra.dev/docs](https://encra.dev/docs) · architecture & crypto notes in the [monorepo](https://github.com/adityayaduvanshi/encra). Licensed **Apache-2.0**.
