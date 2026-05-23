# Encra

**Signal-level end-to-end encryption for any app.**

Encrypt messages, files, forms, and documents — your server never sees the plaintext. Developers get an API key, drop in a hook, and their users get cryptographic privacy without knowing anything about cryptography.

**[Live demo & API keys → encra.dev](https://encra.dev)**

---

## What can you encrypt?

| Use case | Hook | Status |
|---|---|---|
| Real-time chat | `useE2EChat()` | ✅ Available now |
| Files & media | `useE2EFile()` | 🔜 Coming soon |
| Form submissions | `useE2EForm()` | 🔜 Coming soon |
| Database fields | `encryptField()` | 🔜 Coming soon |

The cryptographic primitives in `@encra/core` already support all of the above — the additional hooks are being built.

---

## 5-Minute Quickstart

### 1. Get an API key

Sign up at [encra.dev](https://encra.dev) — free plan, no credit card required. Or [self-host](#self-hosting-guide) your own key server.

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
    apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY,
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

That's it. Data is encrypted on the sender's device and decrypted on the recipient's device. The server only ever sees encrypted blobs.

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
await fetch('https://api.encra.dev/v1/keys', {
  method: 'POST',
  headers: { Authorization: 'Bearer YOUR_API_KEY', 'Content-Type': 'application/json' },
  body: JSON.stringify({ userId: 'alice', publicKey: exportKey(aliceKP.publicKey) }),
})

// Encrypt and send
const bobRes = await fetch('https://api.encra.dev/v1/keys/bob', {
  headers: { Authorization: 'Bearer YOUR_API_KEY' },
})
const { publicKey: bobPubB64 } = await bobRes.json()
const shared  = await deriveSharedSecret(aliceKP.privateKey, importKey(bobPubB64))
const ratchet = await DoubleRatchet.initSender(shared, importKey(bobPubB64))
const msg     = ratchet.encrypt('Hello Bob!')
// send msg.header, msg.ciphertext, msg.nonce to Bob via WebSocket
```

---

## Managed vs Self-Hosted

| | Managed (encra.dev) | Self-Hosted |
|--|-------------------|-------------|
| Setup | Get API key, done | Clone, configure Postgres, deploy |
| Cost | Free tier + paid plans | Your own infra costs |
| Maintenance | Zero | You own it |
| Data location | Encra servers | Wherever you deploy |
| License | — | BUSL 1.1 (see below) |

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
   ├─► Chain Key 1 ──► Message Key 1  (encrypt, then delete key)
   │       │
   │       └─► Chain Key 2 ──► Message Key 2  (encrypt, then delete key)
   │
   └─► (DH ratchet step on direction flip — new root key, new chains)
```

If an attacker compromises today's key:
- **Past data** — safe, those keys are already deleted
- **Future data** — safe after the next DH ratchet step

---

## Security Model

### What we protect against

| Threat | Protection |
|--------|-----------|
| Server compromise | Server stores only public keys + ciphertext blobs. No plaintext, no private keys. |
| MITM / tampering | XSalsa20-Poly1305 authenticated encryption — tampering detected and rejected. |
| Key compromise revealing past data | Double Ratchet with per-message key deletion (forward secrecy). |
| Key compromise revealing future data | DH ratchet rotation on every direction change (break-in recovery). |
| Weak randomness | All nonces and key pairs via libsodium `randombytes_buf` (OS CSPRNG). |

### Cryptographic primitives

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key exchange | X25519 (ECDH) | libsodium `crypto_scalarmult` |
| Encryption | XSalsa20-Poly1305 | libsodium `crypto_secretbox` |
| KDF (ratchet) | Keyed BLAKE2b-256 | libsodium `crypto_generichash` |
| Key generation | X25519 keypair | libsodium `crypto_box_keypair` |
| Safety numbers | BLAKE2b-256 | libsodium `crypto_generichash` |

---

## API Reference

### `@encra/core`

```typescript
// Key pairs
generateKeyPair(): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>
exportKey(key: Uint8Array): string        // → URL-safe base64
importKey(b64: string): Uint8Array

// Key exchange
deriveSharedSecret(myPrivKey: Uint8Array, theirPubKey: Uint8Array): Promise<Uint8Array>

// Double Ratchet
DoubleRatchet.initSender(sharedSecret, theirPublicKey): Promise<DoubleRatchet>
DoubleRatchet.initReceiver(sharedSecret, ourKeyPair): Promise<DoubleRatchet>
ratchet.encrypt(plaintext: string): RatchetMessage
ratchet.decrypt(message: RatchetMessage): string

// Errors
InvalidKeyError / DecryptionFailedError / KeyNotFoundError
```

### `@encra/react`

```typescript
const { messages, isReady, sendMessage, error } = useE2EChat({
  apiKey: string,
  userId: string,
  serverUrl?: string,  // defaults to https://api.encra.dev
})
```

### `encra` CLI

```bash
npx encra init      # Interactive setup wizard — generates .env + starter component
npx encra keygen    # Generate a test X25519 key pair
npx encra ping      # Verify server is reachable and API key is valid
```

### Server REST API

All endpoints require `Authorization: Bearer <api_key>`.

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/health` | `{ ok: true }` |
| `POST` | `/v1/keys` | `201 { userId }` |
| `GET` | `/v1/keys/:userId` | `200 { userId, publicKey }` or `404` |

---

## Self-Hosting Guide

> **Note:** `packages/server` is BUSL 1.1. Self-hosting is permitted for non-commercial use. See [License](#license).

```bash
git clone https://github.com/adityayaduvanshi/encra
cd encra && npm install

# Configure
cp packages/server/.env.example packages/server/.env
# Set DATABASE_URL and JWT_SECRET

# Migrate
psql $DATABASE_URL -f packages/server/migrations/001_init.sql

# Start
cd packages/server && npm run build && npm start
```

---

## Development

```bash
npm install       # Install all deps
npm test          # Run all tests
npm run build     # Build all packages
node e2e-test.mjs # Alice→Bob end-to-end test
```

---

## License

| Package | License |
|---------|---------|
| `packages/core` | Apache 2.0 |
| `packages/react` | Apache 2.0 |
| `packages/cli` | Apache 2.0 |
| `packages/server` | BUSL 1.1 → Apache 2.0 on 2030-01-01 |

For commercial licensing: [legal@encra.dev](mailto:legal@encra.dev)
