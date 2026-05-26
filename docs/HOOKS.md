# Encra React Hooks — API Reference

All three hooks are exported from `@encra/react`. They share the same IndexedDB key
pair per `userId` — mounting all three for the same user only generates one key pair.

---

## useE2EChat

Real-time end-to-end encrypted messaging via WebSocket.

### Signature

```typescript
function useE2EChat(options: UseE2EChatOptions): UseE2EChatResult
```

### Options

```typescript
interface UseE2EChatOptions {
  apiKey:           string          // Developer API key (JWT)
  userId:           string          // Current user's identifier
  serverUrl?:       string          // Default: 'https://api.encra.dev'
  onError?:         (err: Error) => void    // Called for per-message decryption errors
  onWireMessage?:   (event: WireEvent) => void  // Called on every send/receive with raw wire data
}
```

### Result

```typescript
interface UseE2EChatResult {
  messages:     Message[]      // Decrypted message history (persisted in IndexedDB)
  isReady:      boolean        // WebSocket open + registered
  isConnecting: boolean        // Initial connection or reconnect attempt in progress
  sendMessage:  (to: string, text: string) => Promise<void>
  error:        Error | null   // Fatal connection error (null when healthy)
}

interface Message {
  from:      string   // userId of sender
  text:      string   // Decrypted plaintext
  timestamp: number   // Unix ms
}

interface WireEvent {
  direction:  'sent' | 'received'
  ciphertext: string  // base64
  nonce:      string  // base64
  timestamp:  number
}
```

### Behaviour

- On mount: restores key pair from IndexedDB (or generates new one), registers public
  key with server, opens WebSocket, restores message history.
- `sendMessage(to, text)`: fetches all registered devices of `to`, encrypts and sends
  one message per device (multi-device delivery), saves ratchet state to IndexedDB.
- On WebSocket close: exponential backoff reconnect (1s base, 60s max, ±25% jitter).
- On decryption error: calls `onError` (non-fatal, does not break the connection).
- `isReady` becomes `true` only after the relay confirms registration.

### Example

```tsx
const { messages, isReady, isConnecting, sendMessage, error } = useE2EChat({
  apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
  userId: session.user.id,
  onError: (err) => toast.error(err.message),
  onWireMessage: (e) => console.log('wire:', e.ciphertext.slice(0, 16)),
})

// Send
await sendMessage('bob', 'Hello!')

// Render
{messages.map((m, i) => (
  <div key={i} className={m.from === userId ? 'mine' : 'theirs'}>
    {m.text}
  </div>
))}
```

---

## useE2EFile

Encrypt and decrypt `File` / `Blob` objects. One ciphertext envelope per recipient
device. Maximum file size: **50 MB** (`MAX_FILE_BYTES`).

### Signature

```typescript
function useE2EFile(options: UseE2EFileOptions): UseE2EFileResult
```

### Options

```typescript
interface UseE2EFileOptions {
  apiKey:     string
  userId:     string
  serverUrl?: string
  onError?:   (err: Error) => void
}
```

### Result

```typescript
interface UseE2EFileResult {
  encryptFile: (file: File | Blob, recipientId: string) => Promise<EncryptedFile>
  decryptFile: (encrypted: EncryptedFile, senderId: string) => Promise<File>
  isReady:     boolean
  error:       Error | null
}
```

### EncryptedFile shape

```typescript
interface EncryptedFile {
  name:     string   // original filename
  mimeType: string   // original MIME type
  size:     number   // original size in bytes (pre-encryption)
  devices:  Array<{
    deviceId:   string      // recipient device UUID
    ciphertext: Uint8Array  // XSalsa20-Poly1305 encrypted file bytes
    nonce:      Uint8Array  // 24 random bytes
  }>
}
```

### Behaviour

- `encryptFile(file, recipientId)`: fetches all recipient devices, encrypts the file
  independently for each device (fresh nonce per device). Does **not** use the Double
  Ratchet — uses static X25519 ECDH shared secret per device pair.
- `decryptFile(encrypted, senderId)`: finds the envelope addressed to the current
  device, derives the shared secret, decrypts, returns a reconstructed `File`.
- If decryption fails for all sender device keys, throws `DecryptionFailedError`.

### Example

```tsx
const { encryptFile, decryptFile, isReady } = useE2EFile({ apiKey, userId })

// Alice encrypts
const encrypted = await encryptFile(selectedFile, 'bob')
// Send `encrypted` to Bob via your API, database, etc.

// Bob decrypts
const file = await decryptFile(received, 'alice')
const url  = URL.createObjectURL(file)
```

---

## useE2EForm

Encrypt form field values before submission. Each field gets an independent
XSalsa20-Poly1305 ciphertext with a unique nonce. Field **names** are plaintext;
field **values** are encrypted.

### Signature

```typescript
function useE2EForm(options: UseE2EFormOptions): UseE2EFormResult
```

### Options

```typescript
interface UseE2EFormOptions {
  apiKey:     string
  userId:     string
  serverUrl?: string
  onError?:   (err: Error) => void
}
```

### Result

```typescript
interface UseE2EFormResult {
  encryptFields: (
    fields: Record<string, string>,
    recipientId: string
  ) => Promise<EncryptedFields>

  decryptFields: (
    encrypted: EncryptedFields,
    senderId: string
  ) => Promise<Record<string, string>>

  isReady: boolean
  error:   Error | null
}
```

### EncryptedFields shape

```typescript
interface EncryptedFields {
  devices: Array<{
    deviceId: string
    fields:   Record<string, {
      ciphertext: string  // base64
      nonce:      string  // base64
    }>
  }>
}
```

### Behaviour

- `encryptFields(fields, recipientId)`: fetches recipient devices, encrypts each field
  value independently for each device. Field names are visible in the payload; only
  values are encrypted. Does not use Double Ratchet — static X25519 ECDH per device.
- `decryptFields(encrypted, senderId)`: finds own device envelope, decrypts all fields,
  returns a plain object with the original field names and plaintext values.

### Example

```tsx
const { encryptFields, decryptFields, isReady } = useE2EForm({ apiKey, userId })

// Alice (patient) submits a HIPAA intake form
async function handleSubmit(values: Record<string, string>) {
  const payload = await encryptFields(values, doctorId)
  await fetch('/api/intake', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

// Bob (doctor) decrypts
const fields = await decryptFields(payload, patientId)
// { fullName: 'Alice Johnson', ssn: '123-45-6789', ... }
```

---

## E2EChatProvider (optional)

Context provider for sharing `apiKey` and `serverUrl` across multiple `useE2EChat`
instances without prop drilling.

```tsx
import { E2EChatProvider, useE2EChatConfig } from '@encra/react'

// Wrap your app (or chat section)
<E2EChatProvider apiKey="e2e_live_xxx" serverUrl="https://api.encra.dev">
  <ChatComponent />
</E2EChatProvider>

// Inside any child component
function ChatComponent() {
  const { apiKey, serverUrl } = useE2EChatConfig()
  const chat = useE2EChat({ apiKey, userId: 'alice', serverUrl })
}
```

---

## Shared Behaviour Across All Hooks

### Key pair lifecycle
1. On first mount for a `userId`: `generateKeyPair()` → save to IndexedDB → `POST /v1/keys`
2. On subsequent mounts: restore key pair from IndexedDB → `POST /v1/keys` (idempotent upsert)
3. The same key pair is reused by all three hooks for the same `userId`

### Peer key cache
Device public keys for a peer are cached in memory for **5 minutes** (`PEER_KEY_TTL_MS`).
After TTL expiry the next operation re-fetches from the server, picking up any newly
registered devices.

### Error states
- `error` — fatal connection error (key registration failed, WebSocket permanently failed)
- `onError` callback — non-fatal per-operation error (decryption failure, key not found)
- Neither hook throws; all errors surface through state or callback.

---

## @encra/client (EncraClient)

For non-React environments (Node.js, Vue, Svelte, vanilla JS).

```typescript
import { EncraClient } from '@encra/client'

const client = new EncraClient({
  apiKey:     'e2e_live_xxx',
  userId:     'alice',
  serverUrl?: 'https://api.encra.dev',  // optional
})

await client.connect()

// Events
client.on('ready',        ()          => console.log('connected'))
client.on('connecting',   ()          => console.log('reconnecting…'))
client.on('disconnected', ()          => console.log('offline'))
client.on('message',      (msg)       => console.log(msg.from, msg.text))
client.on('error',        (err)       => console.error(err))
client.on('wire',         (event)     => console.log('wire:', event))

// Send
await client.sendMessage('bob', 'Hello!')

// File
const encrypted = await client.encryptFile(file, 'bob')
const file      = await client.decryptFile(encrypted, 'alice')

// Form fields
const payload = await client.encryptFields({ ssn: '...' }, 'bob')
const fields  = await client.decryptFields(payload, 'alice')

// Cleanup
client.disconnect()
```

Same ratchet persistence, multi-device, and reconnect behaviour as the React hooks.
