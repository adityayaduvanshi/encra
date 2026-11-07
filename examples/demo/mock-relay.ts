import type { Plugin, ViteDevServer } from 'vite'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { WebSocketServer, WebSocket } from 'ws'

/**
 * A self-contained, in-memory stand-in for `@encra/server` for local demos.
 *
 * It speaks exactly the HTTP + WebSocket protocol the Encra SDK expects
 * (`/v1/keys`, `/v1/prekeys`, `/v1/relay`) but keeps everything in process
 * memory — no Postgres, no Redis, no JWT. It is NOT a production server: there
 * is no authentication (any bearer token is accepted) and all state is lost when
 * the dev server restarts. It exists only so two browser tabs can run real
 * end-to-end encryption against each other on localhost.
 */

interface PreKeyRecord {
  identityKey:    string
  signedPreKey:   { keyId: number; publicKey: string; signature: string }
  oneTimePreKeys: Array<{ keyId: number; publicKey: string }>
}

export function mockRelay(): Plugin {
  // userId -> (deviceId -> publicKey)
  const keys     = new Map<string, Map<string, string>>()
  // `${userId}:${deviceId}` -> prekey record
  const prekeys  = new Map<string, PreKeyRecord>()
  // `${userId}:${deviceId}` -> live socket
  const clients  = new Map<string, WebSocket>()
  // `${userId}:${deviceId}` -> queued payload strings (offline queue)
  const queue    = new Map<string, string[]>()
  // The DEVELOPER's own app database (NOT part of Encra's zero-knowledge relay):
  // userId -> at-rest message records (ciphertext + queryable metadata). This is
  // what `encryptForStorage` records get persisted into; `decryptFromStorage`
  // reads them back. It only ever holds ciphertext.
  const appDb    = new Map<string, Array<{ id: string; conversationId: string; timestamp: number; ciphertext: string; nonce: string }>>()

  const log = (...a: unknown[]) => console.log('[mock-relay]', ...a)

  function sendJson(res: ServerResponse, status: number, body: unknown): void {
    const text = JSON.stringify(body)
    res.statusCode = status
    res.setHeader('Content-Type', 'application/json')
    res.end(text)
  }

  function readBody(req: IncomingMessage): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let raw = ''
      req.on('data', (c) => { raw += c })
      req.on('end', () => {
        try { resolve(raw ? JSON.parse(raw) : {}) }
        catch { reject(new Error('invalid JSON')) }
      })
      req.on('error', reject)
    })
  }

  function handleHttp(req: IncomingMessage, res: ServerResponse, next: () => void): void {
    const url = req.url ?? ''
    if (!url.startsWith('/v1/') && !url.startsWith('/app/')) return next()
    const { pathname, searchParams } = new URL(url, 'http://localhost')
    const parts = pathname.split('/').filter(Boolean) // ['v1','keys',...]

    void (async () => {
      try {
        // ── POST /v1/keys ───────────────────────────────────────────────────
        if (pathname === '/v1/keys' && req.method === 'POST') {
          const b = (await readBody(req)) as { userId: string; publicKey: string; deviceId?: string }
          const deviceId = b.deviceId ?? 'default'
          if (!keys.has(b.userId)) keys.set(b.userId, new Map())
          keys.get(b.userId)!.set(deviceId, b.publicKey)
          return sendJson(res, 201, { userId: b.userId, deviceId })
        }

        // ── GET /v1/keys/:userId ────────────────────────────────────────────
        if (parts[0] === 'v1' && parts[1] === 'keys' && parts.length === 3 && req.method === 'GET') {
          const userId = decodeURIComponent(parts[2]!)
          const devs = keys.get(userId)
          if (!devs || devs.size === 0) return sendJson(res, 404, { error: `No keys for '${userId}'.` })
          return sendJson(res, 200, {
            userId,
            devices: [...devs.entries()].map(([deviceId, publicKey]) => ({ deviceId, publicKey })),
          })
        }

        // ── POST /v1/prekeys ────────────────────────────────────────────────
        if (pathname === '/v1/prekeys' && req.method === 'POST') {
          const b = (await readBody(req)) as {
            userId: string; deviceId?: string; identityKey: string
            signedPreKey: { keyId: number; publicKey: string; signature: string }
            oneTimePreKeys?: Array<{ keyId: number; publicKey: string }>
          }
          const deviceId = b.deviceId ?? 'default'
          const k = `${b.userId}:${deviceId}`
          const existing = prekeys.get(k)
          prekeys.set(k, {
            identityKey:    b.identityKey,
            signedPreKey:   b.signedPreKey,
            oneTimePreKeys: [...(existing?.oneTimePreKeys ?? []), ...(b.oneTimePreKeys ?? [])],
          })
          return sendJson(res, 201, { userId: b.userId, deviceId, oneTimePreKeyCount: prekeys.get(k)!.oneTimePreKeys.length })
        }

        // ── GET /v1/prekeys/:userId/:deviceId ───────────────────────────────
        if (parts[0] === 'v1' && parts[1] === 'prekeys' && parts.length === 4 && req.method === 'GET') {
          const userId   = decodeURIComponent(parts[2]!)
          const deviceId = decodeURIComponent(parts[3]!)
          const rec = prekeys.get(`${userId}:${deviceId}`)
          if (!rec) return sendJson(res, 404, { error: 'no prekey bundle' })
          const consume = searchParams.get('consumeOneTime') !== 'false'
          const otp = consume ? rec.oneTimePreKeys.shift() : rec.oneTimePreKeys[0]
          return sendJson(res, 200, {
            identityKey:  rec.identityKey,
            signedPreKey: rec.signedPreKey,
            ...(otp ? { oneTimePreKey: otp } : {}),
          })
        }

        // ── POST /app/messages — the developer's DB persists one at-rest record ─
        if (pathname === '/app/messages' && req.method === 'POST') {
          const b = (await readBody(req)) as {
            userId: string
            record: { id: string; conversationId: string; timestamp: number; ciphertext: string; nonce: string }
          }
          const list = appDb.get(b.userId) ?? []
          if (!list.some((r) => r.id === b.record.id)) list.push(b.record)  // dedupe by id
          appDb.set(b.userId, list)
          return sendJson(res, 201, { ok: true, count: list.length })
        }

        // ── GET /app/messages — paginated load (newest-first) ──────────────────
        //   ?userId=&conversationId=&limit=&before=<timestamp>
        if (pathname === '/app/messages' && req.method === 'GET') {
          const uid    = searchParams.get('userId') ?? ''
          const convId = searchParams.get('conversationId')
          const limit  = Math.min(parseInt(searchParams.get('limit') ?? '20', 10) || 20, 200)
          const before = searchParams.get('before') ? Number(searchParams.get('before')) : null
          let rows = (appDb.get(uid) ?? []).slice()
          if (convId) rows = rows.filter((r) => r.conversationId === convId)
          rows.sort((a, b) => b.timestamp - a.timestamp)               // newest first
          if (before !== null) rows = rows.filter((r) => r.timestamp < before)
          const page = rows.slice(0, limit)
          const nextBefore = rows.length > limit ? page[page.length - 1]!.timestamp : null
          return sendJson(res, 200, { records: page, nextBefore })
        }

        // ── POST /app/reset — clear the developer DB (demo "reset" button) ─────
        if (pathname === '/app/reset' && req.method === 'POST') {
          appDb.clear()
          return sendJson(res, 200, { ok: true })
        }

        return sendJson(res, 404, { error: 'not found' })
      } catch (err) {
        sendJson(res, 400, { error: err instanceof Error ? err.message : 'bad request' })
      }
    })()
  }

  function handleRelayConnection(ws: WebSocket): void {
    let userId:   string | null = null
    let deviceId: string | null = null
    let key:      string | null = null

    ws.on('message', (raw) => {
      let msg: Record<string, unknown>
      try { msg = JSON.parse(raw.toString()) } catch { return }

      switch (msg['type']) {
        case 'auth':
          // Demo server trusts any token.
          ws.send(JSON.stringify({ type: 'authenticated' }))
          return

        case 'register': {
          userId   = String(msg['userId'])
          deviceId = String(msg['deviceId'])
          key      = `${userId}:${deviceId}`
          clients.set(key, ws)
          ws.send(JSON.stringify({ type: 'registered', userId, deviceId }))
          // Flush any queued offline messages, deleting each only after sending.
          const pending = queue.get(key) ?? []
          queue.set(key, [])
          for (const payload of pending) {
            if (ws.readyState === WebSocket.OPEN) ws.send(payload)
          }
          log(`registered ${key} (flushed ${pending.length})`)
          return
        }

        case 'message':
        case 'presence': {
          if (!key) { ws.send(JSON.stringify({ type: 'error', message: 'register first' })); return }
          const to       = String(msg['to'])
          const toDevice  = String(msg['toDeviceId'])
          const recipient = `${to}:${toDevice}`
          const payload   = JSON.stringify({
            type:         msg['type'],
            from:         userId,
            fromDeviceId: deviceId,
            ciphertext:   msg['ciphertext'],
            nonce:        msg['nonce'],
            ...(msg['encHeader'] !== undefined && { encHeader: msg['encHeader'] }),
            ...(msg['prekey']    !== undefined && { prekey:    msg['prekey'] }),
          })
          const sock = clients.get(recipient)
          if (sock?.readyState === WebSocket.OPEN) {
            sock.send(payload)
          } else if (msg['type'] === 'message') {
            // Presence is ephemeral (never queued); messages queue for offline.
            const q = queue.get(recipient) ?? []
            q.push(payload)
            queue.set(recipient, q)
          }
          return
        }

        default:
          ws.send(JSON.stringify({ type: 'error', message: `unknown type: ${String(msg['type'])}` }))
      }
    })

    ws.on('close', () => {
      if (key && clients.get(key) === ws) clients.delete(key)
    })
  }

  return {
    name: 'encra-mock-relay',
    configureServer(server: ViteDevServer) {
      server.middlewares.use(handleHttp)

      const wss = new WebSocketServer({ noServer: true })
      wss.on('connection', handleRelayConnection)

      server.httpServer?.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
        // Only claim /v1/relay; let Vite's own HMR websocket handle everything else.
        if (!req.url?.startsWith('/v1/relay')) return
        wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req))
      })

      log('mounted /v1/keys, /v1/prekeys, /v1/relay (in-memory, no DB)')
    },
  }
}
