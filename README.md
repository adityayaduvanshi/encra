# Encra

**Signal-level end-to-end encryption for any app.**

Add encrypted chat to your app in minutes. Developers get an API key, drop in the SDK, and their users get encrypted messaging — without knowing anything about cryptography. Your server never sees plaintext messages, private keys, or shared secrets.

**[Live demo & API keys → encra.dev](https://encra.dev)**

---

## 5-Minute Quickstart

### 1. Get an API key

Sign up at [Encra](https://encra.dev) — free plan, no credit card required. Or [self-host](#self-hosting-guide) your own key server.

### 2. Install

```bash
# Core crypto (works in Node.js, browser, React Native)
npm install @encra/core

# React hook
npm install @encra/react

# Or run the setup wizard
npx encra init
```

### 3. Add to your React app

```tsx
import { useE2EChat } from '@encra/react'

function Chat({ currentUser, recipient }) {
  const { messages, isReady, sendMessage } = useE2EChat({
    apiKey: process.env.REACT_APP_E2E_API_KEY,
    userId: currentUser,
    // serverUrl optional — defaults to Encra managed server
  })

  return (
    <div>
      {messages.map((m, i) => (
        <p key={i}><strong>{m.from}:</strong> {m.text}</p>
      ))}
      <button disabled={!isReady} onClick={() => sendMessage(recipient, 'Hello!')}>
        Send encrypted message
      </button>
    </div>
  )
}
```

That's it. Messages are encrypted on the sender's device and decrypted on the recipient's device. The server only ever sees encrypted blobs.

### 4. Use without React

```typescript
import {
  generateKeyPair,
  deriveSharedSecret,
  exportKey,
  importKey,
  DoubleRatchet,
} from '@encra/core'

// Register user
const aliceKP = await generateKeyPair()
await fetch('https://keys.encra.dev/v1/keys', {
  method: 'POST',
  headers: { Authorization: 'Bearer YOUR_API_KEY', 'Content-Type': 'application/json' },
  body: JSON.stringify({ userId: 'alice', publicKey: exportKey(aliceKP.publicKey) }),
})

// Send an encrypted message to Bob
const bobRes = await fetch('https://keys.encra.dev/v1/keys/bob', {
  headers: { Authorization: 'Bearer YOUR_API_KEY' },
})
const { publicKey: bobPubB64 } = await bobRes.json()
const shared  = await deriveSharedSecret(aliceKP.privateKey, importKey(bobPubB64))
const ratchet = await DoubleRatchet.initSender(shared, importKey(bobPubB64))
const msg     = await ratchet.encrypt('Hello Bob!')
// send msg.header, msg.ciphertext, msg.nonce to Bob via WebSocket
```

---

## Managed vs Self-Hosted

| | Managed (Encra) | Self-Hosted |
|--|-------------------|-------------|
| Setup | Get API key, done | Clone, configure Postgres, deploy |
| Cost | Free tier + paid plans | Your own infra costs |
| Maintenance | Zero | You own it |
| SLA | 99.9% (Pro) | Your responsibility |
| Data location | Our servers | Wherever you deploy |
| License | — | BUSL 1.1 (see below) |

The server source code is available for self-hosting under the [Business Source License](#license). The SDK (`core`, `react`, `cli`) is Apache 2.0 — use it anywhere.

---

## How the Encryption Works

```
Alice's device                    Server                    Bob's device
─────────────────                 ──────                    ────────────
generateKeyPair()
POST publicKey ──────────────────► store(alice → pubKey)
                                   store(bob   → pubKey) ◄── POST publicKey
                                                               generateKeyPair()

GET bob's pubKey ◄───────────────► GET alice's pubKey
deriveSharedSecret()                                      deriveSharedSecret()
  (never leaves device)                                     (never leaves device)

DoubleRatchet.encrypt("Hello!")
  │  message key used once, then deleted
  ▼
{ header, ciphertext, nonce } ───► relay ──────────────► DoubleRatchet.decrypt()
                                  (sees only                "Hello!"
                                   encrypted blob)
```

### Double Ratchet (forward secrecy)

Every message uses a **different encryption key**, derived from a ratchet chain:

```
Root Key
   │
   ├─► Chain Key 1 ──► Message Key 1  (encrypt msg 1, then delete key)
   │       │
   │       └─► Chain Key 2 ──► Message Key 2  (encrypt msg 2, then delete key)
   │               │
   │               └─► Chain Key 3 ──► Message Key 3  ...
   │
   └─► (DH ratchet step when direction flips — new root key, new chains)
```

If an attacker compromises today's key:
- **Past messages** — safe, those keys are already deleted
- **Future messages** — safe after the next DH ratchet step

---

## Security Model

### What we protect against

| Threat | Protection |
|--------|-----------|
| Server compromise | Server stores only public keys + ciphertext blobs. No plaintext, no private keys, no shared secrets. |
| Message interception (MITM) | XSalsa20-Poly1305 authenticated encryption — tampering detected and rejected. |
| Key compromise revealing past messages | Double Ratchet with per-message key deletion (forward secrecy). |
| Key compromise revealing future messages | DH ratchet rotation on every direction change (break-in recovery). |
| Weak randomness | All nonces and key pairs via libsodium `randombytes_buf` (OS CSPRNG). |

### What we do NOT protect against

| Threat | Why |
|--------|-----|
| Compromised endpoint | If the device has malware, the attacker reads plaintext before encryption. No E2E system protects against this. |
| Metadata | The server can see who is talking to whom and when — not what they're saying. |
| Unverified fingerprints | Without comparing safety numbers out-of-band, a compromised server could substitute keys. |

### Cryptographic primitives

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key exchange | X25519 (ECDH) | libsodium `crypto_scalarmult` |
| Message encryption | XSalsa20-Poly1305 | libsodium `crypto_secretbox` |
| KDF (ratchet) | Keyed BLAKE2b-256 | libsodium `crypto_generichash` |
| Key generation | X25519 keypair | libsodium `crypto_box_keypair` |
| Safety numbers | BLAKE2b-256 | libsodium `crypto_generichash` |

---

## API Reference

### `packages/core`

#### Key pairs

```typescript
generateKeyPair(): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>
exportKey(key: Uint8Array): string   // → URL-safe base64
importKey(b64: string): Uint8Array
```

#### Key exchange

```typescript
deriveSharedSecret(myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Promise<Uint8Array>
```

#### Encryption (single message, no ratchet)

```typescript
encrypt(plaintext: string, sharedSecret: Uint8Array): Promise<{ ciphertext: Uint8Array, nonce: Uint8Array }>
decrypt(ciphertext: Uint8Array, nonce: Uint8Array, sharedSecret: Uint8Array): Promise<string>
```

#### Double Ratchet (recommended for conversations)

```typescript
// Initialise
DoubleRatchet.initSender(sharedSecret, theirPublicKey): Promise<DoubleRatchet>
DoubleRatchet.initReceiver(sharedSecret, ourKeyPair): Promise<DoubleRatchet>

// Use
ratchet.encrypt(plaintext: string): Promise<RatchetMessage>
ratchet.decrypt(message: RatchetMessage): Promise<string>

// Persist (store in IndexedDB — never localStorage)
ratchet.export(): RatchetStateExport
DoubleRatchet.fromExport(state: RatchetStateExport): Promise<DoubleRatchet>
```

#### Safety numbers

```typescript
generateFingerprint(publicKey: Uint8Array): Promise<string>
// → "05371 28491 63827 ..." (compare out-of-band to verify identity)
```

#### Errors

```typescript
InvalidKeyError        // Bad key length or format
DecryptionFailedError  // Wrong key, tampered ciphertext, or replayed message
KeyNotFoundError       // User has not registered a public key
```

### `packages/server` — REST API

All endpoints require `Authorization: Bearer <api_key>`.

| Method | Path | Body / Response |
|--------|------|-----------------|
| `GET` | `/health` | `{ ok: true }` |
| `POST` | `/v1/keys` | Body: `{ userId, publicKey: base64 }` → `201 { userId }` |
| `GET` | `/v1/keys/:userId` | `200 { userId, publicKey: base64 }` or `404` |

#### WebSocket relay — `ws://host/v1/relay?token=<jwt>`

```jsonc
// Register after connecting
{ "type": "register", "userId": "alice" }
// ← { "type": "registered", "userId": "alice" }

// Send an encrypted message
{ "type": "message", "to": "bob", "ciphertext": "...", "nonce": "...", "header": { ... } }
// Bob receives:
{ "type": "message", "from": "alice", "ciphertext": "...", "nonce": "...", "header": { ... } }
```

Messages sent while the recipient is offline are queued in Postgres and delivered on reconnect.

### `packages/react`

```typescript
const { messages, isReady, sendMessage, error } = useE2EChat({
  apiKey: string,
  userId: string,
  serverUrl: string,
})

// messages: Array<{ from: string, text: string, timestamp: number }>
// sendMessage(to: string, text: string): Promise<void>
// isReady: boolean — true once keys are registered and WebSocket connected
// error: Error | null
```

```tsx
// Optional context provider — avoids passing apiKey/serverUrl everywhere
<E2EChatProvider apiKey="..." serverUrl="...">
  <YourApp />
</E2EChatProvider>
```

### `packages/cli`

```bash
npx encra init    # Interactive setup wizard
npx encra keygen  # Generate a test key pair
```

---

## Self-Hosting Guide

> **Note:** `packages/server` is licensed under BUSL 1.1. Self-hosting is permitted for non-commercial and development use. See [License](#license) for details.

### Prerequisites

- Node.js 18+
- PostgreSQL 14+

### 1. Clone and install

```bash
git clone https://github.com/adityayaduvanshi/encra
cd encra
npm install
```

### 2. Configure environment

```bash
cp packages/server/.env.example packages/server/.env
```

```env
DATABASE_URL=postgresql://user:password@localhost:5432/e2echat
JWT_SECRET=your-secret-key-min-32-chars-change-this
PORT=3000
```

### 3. Run database migration

```bash
psql $DATABASE_URL -f packages/server/migrations/001_init.sql
```

### 4. Start the server

```bash
cd packages/server
npm run build
npm start
```

### 5. Generate an API key

```bash
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({ developerId: 'my-app' }, process.env.JWT_SECRET, { expiresIn: '1y' }));
"
```

---

## Development

```bash
# Install all dependencies
npm install

# Run all tests
npm test

# Run a specific package
cd packages/core && npm test

# Live end-to-end test (requires server running on port 3000)
node e2e-test.mjs

# Build all packages
npm run build
```

### Test coverage

| Package | Statements | Branches |
|---------|-----------|---------|
| core | ≥ 90% | ≥ 90% |
| server | ≥ 90% | ≥ 85% |
| react | ≥ 85% | ≥ 75% |
| cli | ≥ 85% | ≥ 80% |

---

## License

This is a multi-package repository. Each package has its own license:

| Package | License | SPDX |
|---------|---------|------|
| `packages/core` | Apache License 2.0 | `Apache-2.0` |
| `packages/react` | Apache License 2.0 | `Apache-2.0` |
| `packages/cli` | Apache License 2.0 | `Apache-2.0` |
| `packages/server` | Business Source License 1.1 | `BUSL-1.1` |

**Apache 2.0** (`core`, `react`, `cli`) — use freely in any project, commercial or otherwise. See [`LICENSE`](./LICENSE).

**BUSL 1.1** (`server`) — free for non-commercial and non-production use (development, self-hosting for personal projects). Commercial hosted-service use requires a license from Encra. On **2030-01-01** this automatically converts to Apache 2.0. See [`packages/server/LICENSE`](./packages/server/LICENSE).

For commercial licensing inquiries: [aditya97y@gmail.com](mailto:aditya97y@gmail.com)
