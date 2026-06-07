# @encra/client

[![npm](https://img.shields.io/npm/v/@encra/client?color=22c55e)](https://www.npmjs.com/package/@encra/client)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)

**Signal-grade end-to-end encryption for any JavaScript app — no framework required.** A single `EncraClient` class for encrypted chat, files, forms, and presence. Use it with Vue, Svelte, Angular, vanilla JS, Node.js, or anything else.

Part of [**Encra**](https://encra.dev) — *"Stripe for end-to-end encryption."* (React users: see [`@encra/react`](https://www.npmjs.com/package/@encra/react).)

## Install

```bash
npm install @encra/client
```

Get a free API key at [encra.dev](https://encra.dev).

## Quick start

```ts
import { EncraClient } from '@encra/client'

const client = new EncraClient({ apiKey: process.env.ENCRA_API_KEY!, userId: 'alice' })

client.on('ready',    ()    => console.log('🔒 connected'))
client.on('message',  (msg) => console.log(`${msg.from}: ${msg.text}`))
client.on('presence', (e)   => console.log(e.from, e.payload.status))

await client.connect()
await client.sendMessage('bob', 'Hello, Bob!')
```

## Capabilities

```ts
// Messaging (X3DH + Double Ratchet, multi-device, offline queue)
await client.sendMessage(to, text)

// Files (≤ 50 MB) and form fields
await client.encryptFile(file, to)        // → EncryptedFile
await client.encryptFields(fields, to)    // → EncryptedFields

// Presence — status, typing, last-seen, ghost mode
await client.sendPresence(to, { status: 'online', lastSeenAt: Date.now(), isTyping: false })
await client.setGhostMode(true)

// Events: 'ready' | 'connecting' | 'disconnected' | 'message' | 'presence' | 'error' | 'wire'
```

## How it works

On-device X25519 + X3DH keys (persisted to IndexedDB), Double Ratchet with header encryption for messages, automatic multi-device fan-out, and an auto-reconnecting WebSocket relay with offline queuing. The server only ever holds public keys and ciphertext.

## Docs & license

API reference at [encra.dev/docs](https://encra.dev/docs). Built on [`@encra/core`](https://www.npmjs.com/package/@encra/core). Licensed **Apache-2.0**.
