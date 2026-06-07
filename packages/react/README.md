# @encra/react

[![npm](https://img.shields.io/npm/v/@encra/react?color=22c55e)](https://www.npmjs.com/package/@encra/react)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)

**Signal-grade end-to-end encryption for React — in one hook.** Encrypted chat, files, forms, and presence. Keys are generated on the device; your server only ever sees ciphertext.

Part of [**Encra**](https://encra.dev) — *"Stripe for end-to-end encryption."*

## Install

```bash
npm install @encra/react
# peer dependency: react >= 18
```

Get a free API key at [encra.dev](https://encra.dev), or `npx encra init` to scaffold.

## Hooks

| Hook | Encrypts |
|---|---|
| `useE2EChat` | Real-time messaging (X3DH + Double Ratchet, multi-device, offline queue) |
| `useE2EFile` | `File` / `Blob` up to 50 MB |
| `useE2EForm` | Form field values (HIPAA / GDPR intake) |
| `useE2EPresence` | Online/offline status, typing, last-seen, ghost mode |

## Quick start

```tsx
import { useE2EChat } from '@encra/react'

function Chat({ me, recipient }) {
  const { messages, isReady, sendMessage } = useE2EChat({
    apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
    userId: me,
  })

  return (
    <>
      {messages.map((m, i) => <p key={i}><b>{m.from}:</b> {m.text}</p>)}
      <button disabled={!isReady} onClick={() => sendMessage(recipient, 'Hello!')}>
        Send encrypted
      </button>
    </>
  )
}
```

## Presence

```tsx
import { useE2EPresence } from '@encra/react'

const { presence, ghostMode, setGhostMode, sendTyping } = useE2EPresence({
  apiKey, userId: 'alice', contacts: ['bob', 'carol'],
})

presence['bob']          // { status: 'online', lastSeenAt, isTyping }
await sendTyping('bob', true)
await setGhostMode(true)  // appear offline
```

## How it works

- **On-device keys** — an X25519 key pair + X3DH prekeys are generated per user and stored in IndexedDB (never `localStorage`, never the network).
- **Double Ratchet with header encryption** — forward secrecy, break-in recovery, out-of-order delivery; ratchet state persists across reloads.
- **Multi-device** — messages are encrypted once per recipient device.
- **Resilient transport** — WebSocket relay with exponential-backoff reconnect and offline message queuing.

The key server stores only public keys and encrypted blobs — it is *mathematically* unable to read your users' data.

## Docs & license

API reference: [encra.dev/docs](https://encra.dev/docs) and [`docs/HOOKS.md`](https://github.com/adityayaduvanshi/encra/blob/master/docs/HOOKS.md). Built on [`@encra/core`](https://www.npmjs.com/package/@encra/core). Licensed **Apache-2.0**.
