<h1 align="center">
  <br>
  <a href="https://encra.dev">Encra</a>
  <br>
</h1>

<h3 align="center">Signal-level end-to-end encryption for any app.</h3>

<p align="center">
  One API key. One hook. Your users' data is encrypted on their device before it ever leaves.
  <br>
  Your server never sees plaintext — <em>mathematically guaranteed</em>.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@encra/core"><img src="https://img.shields.io/npm/v/@encra/core?label=%40encra%2Fcore&color=22c55e" alt="@encra/core version"></a>
  <a href="https://www.npmjs.com/package/@encra/react"><img src="https://img.shields.io/npm/v/@encra/react?label=%40encra%2Freact&color=22c55e" alt="@encra/react version"></a>
  <a href="https://www.npmjs.com/package/@encra/client"><img src="https://img.shields.io/npm/v/@encra/client?label=%40encra%2Fclient&color=22c55e" alt="@encra/client version"></a>
  <a href="https://www.npmjs.com/package/encra"><img src="https://img.shields.io/npm/v/encra?label=encra+cli&color=22c55e" alt="encra CLI version"></a>
  <br>
  <a href="https://github.com/adityayaduvanshi/encra/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  <a href="https://encra.dev/docs"><img src="https://img.shields.io/badge/docs-encra.dev-6366f1" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://encra.dev"><strong>Live demo & API keys → encra.dev</strong></a>
</p>

---

## At a glance

```tsx
// React — E2E encrypted chat in 10 lines
import { useE2EChat } from '@encra/react'

function Chat({ me, recipient }) {
  const { messages, isReady, sendMessage } = useE2EChat({
    apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY,
    userId: me,
  })

  return (
    <>
      {messages.map((m, i) => <p key={i}><b>{m.from}:</b> {m.text}</p>)}
      <button disabled={!isReady} onClick={() => sendMessage(recipient, 'Hello!')}>
        Send encrypted message
      </button>
    </>
  )
}
```

> Keys are generated **on the device**. The server stores only public keys and encrypted blobs. Even if the server is hacked, there is nothing readable to steal.

---

## What can you encrypt?

| Use case | React | Vanilla / Vue / Svelte / Node |
|---|---|---|
| Real-time chat | `useE2EChat()` | `EncraClient.sendMessage()` |
| Files & media (≤50 MB) | `useE2EFile()` | `EncraClient.encryptFile()` |
| Form submissions | `useE2EForm()` | `EncraClient.encryptFields()` |
| Database columns | `encryptField()` from `@encra/core` | same |

---

## Packages

| Package | Description |
|---|---|
| [`@encra/core`](packages/core) | Pure crypto primitives — X25519, XSalsa20-Poly1305, Double Ratchet, BLAKE2b. Zero framework deps. |
| [`@encra/react`](packages/react) | React hooks — `useE2EChat`, `useE2EFile`, `useE2EForm`. |
| [`@encra/client`](packages/client) | Framework-agnostic `EncraClient` — Vue, Svelte, Angular, vanilla JS, Node.js. |
| [`@encra/server`](packages/server) | Self-hostable key server + WebSocket relay (BUSL 1.1). |
| [`encra`](packages/cli) | CLI — `npx encra init`, `keygen`, `ping`. |

---

## Quickstart

### 1. Get an API key

Sign up at [encra.dev](https://encra.dev) — free plan, no credit card required.

```bash
# Or scaffold everything interactively:
npx encra init
```

### 2. Install

```bash
# React
npm install @encra/react

# Vue · Svelte · Angular · vanilla JS · Node.js
npm install @encra/client

# Low-level crypto only (no server, no WebSocket)
npm install @encra/core
```

---

## Usage examples

### Encrypted chat — React

```tsx
import { useE2EChat } from '@encra/react'

function ChatRoom({ userId, recipientId }) {
  const { messages, isReady, isConnecting, sendMessage, error } = useE2EChat({
    apiKey:   process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
    userId,
    onError:  (err) => console.error('Encra error:', err),
  })

  if (isConnecting) return <p>Connecting…</p>
  if (error)        return <p>Error: {error.message}</p>

  return (
    <div>
      <ul>
        {messages.map((m, i) => (
          <li key={i}><strong>{m.from}:</strong> {m.text}</li>
        ))}
      </ul>
      <button disabled={!isReady} onClick={() => sendMessage(recipientId, 'Hey!')}>
        Send
      </button>
    </div>
  )
}
```

### Encrypted chat — Vue

```ts
// composable: useEncraChat.ts
import { ref, onMounted, onUnmounted } from 'vue'
import { EncraClient } from '@encra/client'

export function useEncraChat(userId: string) {
  const messages = ref<{ from: string; text: string }[]>([])
  const isReady  = ref(false)
  const client   = new EncraClient({ apiKey: import.meta.env.VITE_ENCRA_KEY, userId })

  onMounted(async () => {
    client.on('message', () => { messages.value = [...client.messages] })
    client.on('ready',   () => { isReady.value  = true })
    await client.connect()
  })

  onUnmounted(() => client.disconnect())

  return { messages, isReady, sendMessage: client.sendMessage.bind(client) }
}
```

### Encrypted chat — Vanilla JS / Node.js

```ts
import { EncraClient } from '@encra/client'

const client = new EncraClient({
  apiKey:    process.env.ENCRA_API_KEY,
  userId:    'alice',
  serverUrl: 'https://api.encra.dev', // optional — this is the default
})

client.on('ready',   ()    => console.log('🔒 Connected'))
client.on('message', (msg) => console.log(`${msg.from}: ${msg.text}`))
client.on('error',   (err) => console.error(err))

await client.connect()
await client.sendMessage('bob', 'Hello, Bob!')

// Read state at any time
console.log(client.isReady, client.messages)

client.disconnect()
```

### Encrypted file upload — React

```tsx
import { useE2EFile } from '@encra/react'

function FileShare({ userId, recipientId }) {
  const { encryptFile, isReady } = useE2EFile({
    apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
    userId,
  })

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return

    // Encrypt on the device — server never sees the contents
    const encrypted = await encryptFile(file, recipientId)

    // Upload the ciphertext however you like (S3, R2, your DB, etc.)
    await fetch('/api/files', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(encrypted),  // ← only encrypted bytes leave the device
    })
  }

  return <input type="file" disabled={!isReady} onChange={handleUpload} />
}
```

### Encrypted form — React (HIPAA / GDPR)

```tsx
import { useE2EForm } from '@encra/react'

function MedicalForm({ patientId, doctorId }) {
  const { encryptFields, isReady } = useE2EForm({
    apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
    userId: patientId,
  })

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const data = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>

    // Only the doctor can decrypt — your server stores ciphertext only
    const encrypted = await encryptFields(data, doctorId)

    await fetch('/api/intake', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(encrypted),
    })
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="ssn"           placeholder="SSN"          />
      <input name="dateOfBirth"   placeholder="Date of birth"/>
      <input name="chiefComplaint"placeholder="Chief complaint"/>
      <button disabled={!isReady} type="submit">Submit (encrypted)</button>
    </form>
  )
}
```

### Database field encryption — no server needed

```ts
import { generateFieldKey, encryptField, decryptField } from '@encra/core'

// Generate once and store in a secrets manager (AWS Secrets Manager, Vault, etc.)
const key = await generateFieldKey()  // 32-byte symmetric key

// Encrypt before INSERT
const encryptedSSN = await encryptField('123-45-6789', key)
// → { ciphertext: "base64...", nonce: "base64..." }
// INSERT INTO patients (ssn_ciphertext, ssn_nonce) VALUES (?, ?)

// Decrypt after SELECT
const ssn = await decryptField(encryptedSSN, key)
// → "123-45-6789"
```

---

## How the encryption works

```
Alice's device                    Server                    Bob's device
─────────────────                 ──────                    ────────────
generateKeyPair()
POST publicKey ──────────────────► store(alice → pubKey)
                                   store(bob   → pubKey) ◄── generateKeyPair()
                                                               POST publicKey

GET bob's pubKey ◄──────────────►  GET alice's pubKey
deriveSharedSecret()                                      deriveSharedSecret()
  (never leaves device)                                     (never leaves device)

DoubleRatchet.encrypt("Hello!")
  │  one-time key derived, used once, then deleted
  ▼
{ header, ciphertext, nonce } ───► relay ──────────────► DoubleRatchet.decrypt()
                                  (sees only                "Hello!"
                                   encrypted blob)
```

### Double Ratchet — forward secrecy + break-in recovery

Every message uses a **different, one-time encryption key**:

```
Root Key
   │
   ├─► Chain Key 1 ──► Message Key 1  (used once, then deleted)
   │       │
   │       └─► Chain Key 2 ──► Message Key 2  (used once, then deleted)
   │
   └─► (DH ratchet step on every direction flip — new root key, new chains)
```

| If an attacker steals a key… | Impact |
|---|---|
| Past messages | ✅ Safe — those keys are already deleted |
| Future messages | ✅ Safe after the next DH ratchet step |

This is the same protocol used by Signal, WhatsApp, and iMessage.

---

## FAQ

### What problem does Encra solve?

Most apps store user data in plaintext on their servers. A single breach — or a subpoena — exposes everything. Encra moves encryption to the client so your server becomes mathematically incapable of reading user data, not just policy-incapable.

Developers shouldn't need a PhD in cryptography to ship private apps. Encra packages the Signal Protocol into a single hook or class, handling key generation, key exchange, ratchet state persistence, reconnection, and error surfacing — so you don't have to.

### Why not use raw Web Crypto?

You could. But you'd need to:

- Implement X25519 key exchange correctly
- Implement Double Ratchet from scratch (forward secrecy, out-of-order messages, MAX_SKIP, state persistence)
- Build a key server and WebSocket relay
- Handle key registration, peer key lookup, and offline delivery
- Deal with reconnects, backoff, and error surfacing
- Persist ratchet state to IndexedDB across page reloads
- Test all of the above with cryptographic test vectors

Encra is the production-grade version of that work, auditable and open source.

### How secure is it?

Encra uses the same cryptographic primitives as Signal:

| Purpose | Algorithm | Why |
|---|---|---|
| Key exchange | X25519 (ECDH) | Fast, side-channel resistant, 128-bit security |
| Encryption | XSalsa20-Poly1305 | Authenticated encryption, random nonce, no IV reuse |
| KDF / ratchet | Keyed BLAKE2b-256 | Fast, secure, no length-extension attacks |
| Key generation | X25519 keypair | OS CSPRNG via libsodium `randombytes_buf` |
| Key derivation | `crypto_box_beforenm` | Proper ECDH + HSalsa20 — not raw DH output |

The server stores **only** public keys and ciphertext blobs. No plaintext, no private keys, no shared secrets — ever.

### What platforms are supported?

| Platform | Package |
|---|---|
| React 18+ | `@encra/react` |
| Vue 3, Svelte, Angular | `@encra/client` |
| Vanilla JS (browser) | `@encra/client` |
| Node.js 18+ | `@encra/client` or `@encra/core` |
| React Native | `@encra/core` (hooks coming soon) |

### How fast is setup?

Under 5 minutes:

1. `npm install @encra/react` (or `@encra/client`)
2. Set `NEXT_PUBLIC_ENCRA_API_KEY` in your `.env`
3. Drop in `useE2EChat()` (or `new EncraClient()`)
4. Done — your messages are end-to-end encrypted

Or run `npx encra init` for an interactive wizard that writes the env file and a starter component for your framework.

---

## Security model

### What we protect against

| Threat | How |
|---|---|
| Server breach | Server stores only public keys + ciphertext. No plaintext, no private keys. |
| Network interception (MITM) | XSalsa20-Poly1305 authenticated encryption — tampering is detected and rejected. |
| Key compromise exposing past data | Double Ratchet with per-message key deletion (forward secrecy). |
| Key compromise exposing future data | DH ratchet step on every direction change (break-in recovery). |
| Weak randomness | All nonces and key pairs via libsodium `randombytes_buf` (OS CSPRNG). |

### What we do NOT protect against

- **Compromised endpoint** — if the device running your app is fully compromised (malware, physical access), Encra cannot help.
- **Metadata** — Encra encrypts content, not metadata. The server knows *who* communicated and *when*, but not *what*.
- **Key server impersonation** — Encra does not implement certificate pinning or key transparency (yet). Use `generateFingerprint()` for out-of-band verification.

---

## API Reference

### `@encra/react` — hooks

```typescript
// Encrypted real-time chat
const { messages, isReady, isConnecting, sendMessage, error } = useE2EChat({
  apiKey:         string,
  userId:         string,
  serverUrl?:     string,                       // default: https://api.encra.dev
  onError?:       (err: Error) => void,
  onWireMessage?: (event: WireEvent) => void,   // raw wire data
})

// Encrypted file transfer (up to 50 MB)
const { encryptFile, decryptFile, isReady, error } = useE2EFile({
  apiKey:     string,
  userId:     string,
  serverUrl?: string,
  onError?:   (err: Error) => void,
})

// Encrypted form fields
const { encryptFields, decryptFields, isReady, error } = useE2EForm({
  apiKey:     string,
  userId:     string,
  serverUrl?: string,
  onError?:   (err: Error) => void,
})
```

### `@encra/client` — `EncraClient`

```typescript
const client = new EncraClient({ apiKey, userId, serverUrl? })

// Lifecycle
await client.connect()          // resolves when WebSocket is open
client.disconnect()             // close and clean up

// Messaging
await client.sendMessage(to: string, text: string)

// File encryption (≤ 50 MB)
await client.encryptFile(file: File | Blob, to: string)           // → EncryptedFile
await client.decryptFile(encrypted: EncryptedFile, from: string)  // → File

// Form field encryption (independent per-field nonces)
await client.encryptFields(fields: Record<string, string>, to: string)   // → EncryptedFields
await client.decryptFields(encrypted: EncryptedFields, from: string)     // → Record<string, string>

// Synchronous state
client.isReady        // boolean
client.isConnecting   // boolean
client.messages       // Message[]  — sent + received, newest last
client.error          // Error | null

// Events
client.on('ready',        ()      => ...)
client.on('connecting',   ()      => ...)
client.on('disconnected', ()      => ...)
client.on('message',      (msg)   => ...)   // { from, text, timestamp }
client.on('error',        (err)   => ...)   // recoverable errors
client.on('wire',         (event) => ...)   // raw encrypted wire data
client.off(event, listener)
```

### `@encra/core` — primitives

```typescript
import {
  // Key pairs
  generateKeyPair,        // () => Promise<{ publicKey, privateKey }>
  exportKey,              // (key: Uint8Array) => string  (URL-safe base64)
  importKey,              // (b64: string) => Uint8Array
  sodiumReady,            // () => Promise<void>  — await once at startup

  // Key exchange
  deriveSharedSecret,     // (myPrivKey, theirPubKey) => Promise<Uint8Array>

  // Symmetric encryption
  encrypt,                // (plaintext, sharedSecret) => Promise<{ ciphertext, nonce }>
  decrypt,                // ({ ciphertext, nonce }, sharedSecret) => Promise<string>

  // Database field encryption (no server required)
  generateFieldKey,       // () => Promise<Uint8Array>  — 32-byte symmetric key
  encryptField,           // (value, key) => Promise<{ ciphertext, nonce }>
  decryptField,           // (encrypted, key) => Promise<string>

  // Safety numbers
  generateFingerprint,    // (pubKeyA, pubKeyB) => Promise<string>

  // Double Ratchet (advanced)
  DoubleRatchet,

  // Typed errors
  InvalidKeyError,
  DecryptionFailedError,
  KeyNotFoundError,
} from '@encra/core'
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
|---|---|---|
| `GET`  | `/health` | Liveness check |
| `POST` | `/v1/keys` | Register / update a public key |
| `GET`  | `/v1/keys/:userId` | Fetch a user's public key |
| `WS`   | `/v1/relay?token=` | WebSocket relay — routes encrypted messages |

---

## Managed vs self-hosted

| | Managed (encra.dev) | Self-hosted |
|---|---|---|
| Setup | Get an API key, done | Clone, configure Postgres, deploy |
| Cost | Free tier + paid plans | Your own infra costs |
| Maintenance | Zero | You own it |
| Data location | Encra servers (US) | Wherever you deploy |
| License | — | BUSL 1.1 (see below) |

---

## Self-hosting

> **Note:** `packages/server` is licensed under BUSL 1.1. Self-hosting is permitted for non-commercial use. See [License](#license).

```bash
git clone https://github.com/adityayaduvanshi/encra
cd encra && npm install

# Configure
cp packages/server/.env.example packages/server/.env
# Edit .env — set DATABASE_URL and JWT_SECRET

# Migrate
psql $DATABASE_URL -f packages/server/migrations/001_init.sql
psql $DATABASE_URL -f packages/server/migrations/002_message_queue_header.sql

# Build & start
npm run build --workspace=packages/server
npm start     --workspace=packages/server
```

The server exposes `:3000` by default. Point `serverUrl` in your SDK config to your deployment.

---

## Development

```bash
npm install          # Install all workspace deps
npm test             # Run all tests (65 core + 35 react + 25 client + more)
npm run build        # Build all packages
node e2e-test.mjs    # Alice → Bob end-to-end integration test
```

Tests use [Vitest](https://vitest.dev) with cryptographic test vectors — the real libsodium primitives are tested, never mocked.

---

## License

| Package | License |
|---|---|
| `packages/core`   | [Apache 2.0](packages/core/LICENSE) |
| `packages/client` | [Apache 2.0](packages/client/LICENSE) |
| `packages/react`  | [Apache 2.0](packages/react/LICENSE) |
| `packages/cli`    | [Apache 2.0](packages/cli/LICENSE) |
| `packages/server` | [BUSL 1.1](packages/server/LICENSE) → Apache 2.0 on 2030-01-01 |

For commercial self-hosting licenses: [legal@encra.dev](mailto:legal@encra.dev)
