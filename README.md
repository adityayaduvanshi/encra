# Encra

**Signal-level end-to-end encryption for any app.**

Encrypt messages, files, forms, and documents — your server never sees the plaintext. Developers get an API key, drop in a hook or client, and their users get cryptographic privacy without knowing anything about cryptography.

**[Live demo & API keys → encra.dev](https://encra.dev)**

---

## Packages

| Package | Version | Description |
|---|---|---|
| [`@encra/core`](packages/core) | ![npm](https://img.shields.io/npm/v/@encra/core) | Pure crypto primitives — X25519, XSalsa20-Poly1305, Double Ratchet |
| [`@encra/client`](packages/client) | ![npm](https://img.shields.io/npm/v/@encra/client) | Framework-agnostic JS client — works with Vue, Svelte, Angular, vanilla JS, Node.js |
| [`@encra/react`](packages/react) | ![npm](https://img.shields.io/npm/v/@encra/react) | React hook (`useE2EChat`) — thin wrapper around `@encra/client` |
| [`@encra/server`](packages/server) | — | Key server + WebSocket relay (self-host or use encra.dev) |
| [`encra`](packages/cli) | ![npm](https://img.shields.io/npm/v/encra) | CLI — `init`, `keygen`, `ping` |

---

## What can you encrypt?

| Use case | API | Status |
|---|---|---|
| Real-time chat | `useE2EChat()` / `EncraClient` | ✅ Available |
| Files & media | `useE2EFile()` | 🔜 Coming soon |
| Form submissions | `useE2EForm()` | 🔜 Coming soon |
| Database fields | `encryptField()` | 🔜 Coming soon |

---

## Quickstart

### 1. Get an API key

Sign up at [encra.dev](https://encra.dev) — free plan, no credit card required.
Or [self-host](#self-hosting-guide) your own key server.

### 2. Install

```bash
# React
npm install @encra/react

# Vue, Svelte, Angular, vanilla JS, Node.js
npm install @encra/client

# Or run the interactive setup wizard
npx encra init
```

### 3. React

```tsx
import { useE2EChat } from '@encra/react'

function Chat({ currentUser, recipient }) {
  const { messages, isReady, isConnecting, sendMessage } = useE2EChat({
    apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY,
    userId: currentUser,
    onError: (err) => console.error(err),
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

### 4. Vue / Svelte / Vanilla JS / Node.js

```ts
import { EncraClient } from '@encra/client'

const client = new EncraClient({
  apiKey:    process.env.ENCRA_API_KEY,
  userId:    'alice',
  serverUrl: 'https://api.encra.dev', // optional, this is the default
})

client.on('message', (msg) => console.log(msg.from, msg.text))
client.on('ready',   ()    => console.log('connected'))
client.on('error',   (err) => console.error(err))

await client.connect()
await client.sendMessage('bob', 'Hello!')

// Read state at any time
console.log(client.isReady, client.messages)

// Clean up
client.disconnect()
```

**Vue example:**
```ts
// composable: useEncraChat.ts
import { ref, onMounted, onUnmounted } from 'vue'
import { EncraClient } from '@encra/client'

export function useEncraChat(userId: string) {
  const messages   = ref([])
  const isReady    = ref(false)
  const client     = new EncraClient({ apiKey: import.meta.env.VITE_ENCRA_KEY, userId })

  onMounted(async () => {
    client.on('message', () => { messages.value = [...client.messages] })
    client.on('ready',   () => { isReady.value = true })
    await client.connect()
  })

  onUnmounted(() => client.disconnect())

  return { messages, isReady, sendMessage: client.sendMessage.bind(client) }
}
```

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
- **Past messages** — safe, those keys are already deleted
- **Future messages** — safe after the next DH ratchet step

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

### `@encra/client` — `EncraClient`

```typescript
const client = new EncraClient({ apiKey, userId, serverUrl? })

// Lifecycle
await client.connect()     // resolves when WebSocket is open
client.disconnect()        // close and clean up

// Messaging
await client.sendMessage(to: string, text: string)

// State (synchronous reads)
client.isReady        // boolean
client.isConnecting   // boolean
client.messages       // Message[]  — sent + received, newest last
client.error          // Error | null

// Events
client.on('ready',        ()         => ...)
client.on('connecting',   ()         => ...)
client.on('disconnected', ()         => ...)
client.on('message',      (msg)      => ...)  // { from, text, timestamp }
client.on('error',        (err)      => ...)  // recoverable errors
client.on('wire',         (event)    => ...)  // raw encrypted wire data
client.off(event, listener)
```

### `@encra/react` — `useE2EChat`

```typescript
const {
  messages,      // Message[]
  isReady,       // boolean — WebSocket open and registered
  isConnecting,  // boolean — connecting or reconnecting
  sendMessage,   // (to: string, text: string) => Promise<void>
  error,         // Error | null — fatal init errors only
} = useE2EChat({
  apiKey:          string,
  userId:          string,
  serverUrl?:      string,   // defaults to https://api.encra.dev
  onError?:        (err: Error) => void,       // recoverable errors
  onWireMessage?:  (event: WireEvent) => void, // raw wire data
})
```

### `@encra/core`

```typescript
// Key pairs
generateKeyPair(): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>
exportKey(key: Uint8Array): string        // → URL-safe base64
importKey(b64: string): Uint8Array

// Key exchange
deriveSharedSecret(myPrivKey, theirPubKey): Promise<Uint8Array>

// Double Ratchet
DoubleRatchet.initSender(sharedSecret, theirPublicKey): Promise<DoubleRatchet>
DoubleRatchet.initReceiver(sharedSecret, ourKeyPair):   Promise<DoubleRatchet>
ratchet.encrypt(plaintext: string): Promise<RatchetMessage>
ratchet.decrypt(message: RatchetMessage): Promise<string>
ratchet.export(): RatchetStateExport   // persist to storage
DoubleRatchet.fromExport(state): Promise<DoubleRatchet>  // restore

// Errors
InvalidKeyError / DecryptionFailedError / KeyNotFoundError
```

### `encra` CLI

```bash
npx encra init      # Interactive setup — writes .env.example + starter component
npx encra keygen    # Generate a test X25519 key pair + fingerprint
npx encra ping      # Verify server reachability and API key validity
```

### Server REST API

All endpoints require `Authorization: Bearer <api_key>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Liveness check |
| `POST` | `/v1/keys` | Register / update a public key |
| `GET`  | `/v1/keys/:userId` | Fetch a user's public key |
| `WS`   | `/v1/relay?token=` | WebSocket relay — routes encrypted messages |

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

## Self-Hosting Guide

> **Note:** `packages/server` is BUSL 1.1. Self-hosting is permitted for non-commercial use. See [License](#license).

```bash
git clone https://github.com/adityayaduvanshi/encra
cd encra && npm install

# Configure
cp packages/server/.env.example packages/server/.env
# Set DATABASE_URL and JWT_SECRET

# Migrate database
psql $DATABASE_URL -f packages/server/migrations/001_init.sql
psql $DATABASE_URL -f packages/server/migrations/002_message_queue_header.sql

# Build and start
npm run build --workspace=packages/server
npm start     --workspace=packages/server
```

---

## Development

```bash
npm install          # Install all workspace deps
npm test             # Run all tests
npm run build        # Build all packages
node e2e-test.mjs    # Alice→Bob end-to-end integration test
```

---

## License

| Package | License |
|---------|---------|
| `packages/core`   | Apache 2.0 |
| `packages/client` | Apache 2.0 |
| `packages/react`  | Apache 2.0 |
| `packages/cli`    | Apache 2.0 |
| `packages/server` | BUSL 1.1 → Apache 2.0 on 2030-01-01 |

For commercial licensing: [legal@encra.dev](mailto:legal@encra.dev)
