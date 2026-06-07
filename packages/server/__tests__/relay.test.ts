/**
 * WebSocket relay integration test.
 *
 * Spins up a real http.Server on a random port with the WebSocket relay attached.
 * Uses real ws clients — no mocks. Verifies the full message path:
 * Alice connects → registers → sends → Bob receives.
 * Also verifies offline queuing: message queued when Bob is offline, delivered on connect.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import http from 'http'
import { WebSocket } from 'ws'
import jwt from 'jsonwebtoken'
import { vi } from 'vitest'
import type { Pool, QueryResult } from 'pg'
import { createApp } from '../src/app.js'
import { attachWebSocketRelay } from '../src/ws/relay.js'
import { setPool } from '../src/db/pool.js'

const JWT_SECRET = 'test-secret-do-not-use-in-production'

function makeToken(): string {
  return jwt.sign({ developerId: 'test-dev' }, JWT_SECRET, { expiresIn: '1h' })
}

// ── In-memory pool with message queue support ─────────────────────────────────

interface QueueRow {
  id:                  number
  recipient_id:        string
  recipient_device_id: string
  sender_id:           string
  sender_device_id:    string
  ciphertext:          string
  nonce:               string
  enc_header:          string
  prekey:              unknown
  sender_name:         string | null
}

function makePool(): { pool: Pool; keys: Map<string, string>; queue: QueueRow[] } {
  const keys  = new Map<string, string>()
  const queue: QueueRow[] = []
  let nextId = 1

  const pool = {
    query: vi.fn(async (sql: string, params: unknown[]) => {
      const s = sql.trim().toUpperCase().replace(/\s+/g, ' ')

      // Health check
      if (s === 'SELECT 1') {
        return { rows: [{ '?column?': 1 }], rowCount: 1 } as unknown as QueryResult
      }

      // INSERT INTO public_keys (user_id, device_id, public_key) VALUES ($1, $2, $3)
      if (s.startsWith('INSERT INTO PUBLIC_KEYS')) {
        keys.set(params[0] as string, params[2] as string)  // userId → publicKey
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      // SELECT device_id, public_key FROM public_keys WHERE user_id = $1
      if (s.startsWith('SELECT DEVICE_ID, PUBLIC_KEY FROM PUBLIC_KEYS')) {
        const key = keys.get(params[0] as string)
        return key
          ? {
              rows:     [{ device_id: 'default', public_key: key }],
              rowCount: 1,
            } as unknown as QueryResult
          : { rows: [], rowCount: 0 } as unknown as QueryResult
      }

      // INSERT INTO message_queue (recipient_id, recipient_device_id, sender_id,
      //   sender_device_id, ciphertext, nonce, enc_header, prekey, sender_name) VALUES ($1...$9)
      if (s.startsWith('INSERT INTO MESSAGE_QUEUE')) {
        const row: QueueRow = {
          id:                  nextId++,
          recipient_id:        params[0] as string,
          recipient_device_id: params[1] as string,
          sender_id:           params[2] as string,
          sender_device_id:    params[3] as string,
          ciphertext:          params[4] as string,
          nonce:               params[5] as string,
          enc_header:          params[6] as string,
          // Emulate JSONB: relay stores a JSON string; pg returns a parsed object.
          prekey:              params[7] == null ? null : JSON.parse(params[7] as string),
          sender_name:         params[8] as string | null,
        }
        queue.push(row)
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      // DELETE FROM message_queue WHERE recipient_id=$1 AND recipient_device_id=$2
      // RETURNING id, sender_id, sender_device_id, ciphertext, nonce, enc_header, prekey, sender_name
      if (s.startsWith('DELETE FROM MESSAGE_QUEUE')) {
        const recipientId       = params[0] as string
        const recipientDeviceId = params[1] as string
        const pending           = queue.filter(
          (m) => m.recipient_id === recipientId && m.recipient_device_id === recipientDeviceId,
        )
        const remaining = queue.filter(
          (m) => !(m.recipient_id === recipientId && m.recipient_device_id === recipientDeviceId),
        )
        queue.length = 0
        queue.push(...remaining)
        return {
          rows:     pending.map((m) => ({
            id:               m.id,
            sender_id:        m.sender_id,
            sender_device_id: m.sender_device_id,
            ciphertext:       m.ciphertext,
            nonce:            m.nonce,
            enc_header:       m.enc_header,
            prekey:           m.prekey,
            sender_name:      m.sender_name,
          })),
          rowCount: pending.length,
        } as unknown as QueryResult
      }

      return { rows: [], rowCount: 0 } as unknown as QueryResult
    }),
  } as unknown as Pool

  return { pool, keys, queue }
}

// ── Server helpers ────────────────────────────────────────────────────────────

function startServer(): Promise<{ server: http.Server; port: number }> {
  return new Promise((resolve) => {
    const app = createApp()
    const server = http.createServer(app)
    attachWebSocketRelay(server)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number }
      resolve({ server, port: addr.port })
    })
  })
}

function stopServer(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
}

// ── WebSocket client helper ───────────────────────────────────────────────────

interface WsClient {
  ws:       WebSocket
  received: Array<Record<string, unknown>>
  send:     (msg: Record<string, unknown>) => void
  close:    () => void
}

function connectClient(port: number, token: string): Promise<WsClient> {
  return new Promise((resolve, reject) => {
    const received: Array<Record<string, unknown>> = []
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/relay`)

    ws.on('error', reject)
    ws.on('open', () => {
      // Send auth as first message — token never goes in the URL
      ws.send(JSON.stringify({ type: 'auth', token }))
      resolve({
        ws,
        received,
        send:  (msg) => ws.send(JSON.stringify(msg)),
        close: () => ws.close(),
      })
    })
    ws.on('message', (raw) => {
      received.push(JSON.parse(raw.toString()) as Record<string, unknown>)
    })
  })
}

function waitForMessage(
  client:    WsClient,
  predicate: (msg: Record<string, unknown>) => boolean,
  timeoutMs  = 2_000,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error('Timeout waiting for message')), timeoutMs)
    const check    = setInterval(() => {
      const msg = client.received.find(predicate)
      if (msg) {
        clearInterval(check)
        clearTimeout(deadline)
        resolve(msg)
      }
    }, 20)
  })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('WebSocket relay', () => {
  let server: http.Server
  let port:   number
  let token:  string

  beforeEach(async () => {
    const db = makePool()
    setPool(db.pool)
    process.env['JWT_SECRET'] = JWT_SECRET
    token = makeToken()
    const started = await startServer()
    server = started.server
    port   = started.port
  })

  afterEach(async () => {
    await stopServer(server)
  })

  it('rejects connection when auth message contains invalid token', async () => {
    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/relay`)
      ws.on('open', () => {
        ws.send(JSON.stringify({ type: 'auth', token: 'bad.token.here' }))
      })
      ws.on('close', (code) => {
        if (code === 4001) resolve()
        else reject(new Error(`Expected close code 4001, got ${code}`))
      })
      ws.on('error', () => {})
      setTimeout(() => reject(new Error('timeout waiting for close')), 2_000)
    })
  })

  it('rejects connection when non-auth message is sent before authenticating', async () => {
    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/relay`)
      ws.on('open', () => {
        ws.send(JSON.stringify({ type: 'register', userId: 'alice', deviceId: 'dev' }))
      })
      ws.on('close', (code) => {
        if (code === 4001) resolve()
        else reject(new Error(`Expected close code 4001, got ${code}`))
      })
      ws.on('error', () => {})
      setTimeout(() => reject(new Error('timeout waiting for close')), 2_000)
    })
  })

  it('sends registered confirmation after register message with userId + deviceId', async () => {
    const alice = await connectClient(port, token)
    alice.send({ type: 'register', userId: 'alice', deviceId: 'alice-device' })

    const msg = await waitForMessage(alice, (m) => m['type'] === 'registered')
    expect(msg['userId']).toBe('alice')
    expect(msg['deviceId']).toBe('alice-device')
    alice.close()
  })

  it('returns error when register message is missing deviceId', async () => {
    const client = await connectClient(port, token)
    client.send({ type: 'register', userId: 'alice' })  // missing deviceId

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('deviceId')
    client.close()
  })

  it('Alice sends a message and Bob receives it in real time', async () => {
    const alice = await connectClient(port, token)
    const bob   = await connectClient(port, token)

    alice.send({ type: 'register', userId: 'alice-relay', deviceId: 'alice-dev' })
    bob.send({   type: 'register', userId: 'bob-relay',   deviceId: 'bob-dev'   })

    await waitForMessage(alice, (m) => m['type'] === 'registered')
    await waitForMessage(bob,   (m) => m['type'] === 'registered')

    alice.send({
      type:       'message',
      to:         'bob-relay',
      toDeviceId: 'bob-dev',
      ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
      nonce:      'dGVzdC1ub25jZQ',
      encHeader:  'ZW5jLWhlYWRlcg',
    })

    const received = await waitForMessage(bob, (m) => m['type'] === 'message')
    expect(received['from']).toBe('alice-relay')
    expect(received['fromDeviceId']).toBe('alice-dev')
    expect(received['ciphertext']).toBe('dGVzdC1jaXBoZXJ0ZXh0')
    expect(received['nonce']).toBe('dGVzdC1ub25jZQ')
    expect(received['encHeader']).toBe('ZW5jLWhlYWRlcg')

    alice.close()
    bob.close()
  })

  it('message is queued when recipient is offline and delivered on connect', async () => {
    const alice = await connectClient(port, token)
    alice.send({ type: 'register', userId: 'alice-queue', deviceId: 'alice-dev' })
    await waitForMessage(alice, (m) => m['type'] === 'registered')

    // Bob is not connected — message should be queued
    alice.send({
      type:       'message',
      to:         'bob-queue',
      toDeviceId: 'bob-dev',
      ciphertext: 'cXVldWVkLW1lc3NhZ2U',
      nonce:      'cXVldWVkLW5vbmNl',
      encHeader:  'cXVldWVkLWhlYWRlcg',
      prekey:     { identityKey: 'ik', ephemeralKey: 'ek', signedPreKeyId: 1, oneTimePreKeyId: 1 },
    })

    // Give the server a moment to process the queue insert
    await new Promise((r) => setTimeout(r, 100))

    // Bob connects and registers — queued message should be flushed
    const bob = await connectClient(port, token)
    bob.send({ type: 'register', userId: 'bob-queue', deviceId: 'bob-dev' })

    const queued = await waitForMessage(bob, (m) => m['type'] === 'message')
    expect(queued['from']).toBe('alice-queue')
    expect(queued['ciphertext']).toBe('cXVldWVkLW1lc3NhZ2U')
    // The encrypted header and X3DH prekey must survive the offline queue round-trip.
    expect(queued['encHeader']).toBe('cXVldWVkLWhlYWRlcg')
    expect(queued['prekey']).toMatchObject({ signedPreKeyId: 1, oneTimePreKeyId: 1 })

    alice.close()
    bob.close()
  })

  it('returns error for message sent without prior register', async () => {
    const client = await connectClient(port, token)
    client.send({
      type: 'message', to: 'someone', toDeviceId: 'dev', ciphertext: 'abc', nonce: 'xyz',
    })

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('register')
    client.close()
  })

  it('returns error for unknown message type', async () => {
    const client = await connectClient(port, token)
    client.send({ type: 'ping' })

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('Unknown')
    client.close()
  })

  it('returns error for invalid JSON', async () => {
    const client = await connectClient(port, token)
    client.ws.send('not-json{{{')

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('JSON')
    client.close()
  })

  it('returns error for message missing required fields', async () => {
    const client = await connectClient(port, token)
    client.send({ type: 'register', userId: 'test-user', deviceId: 'test-dev' })
    await waitForMessage(client, (m) => m['type'] === 'registered')

    client.send({ type: 'message', to: 'someone', toDeviceId: 'their-dev' }) // missing ciphertext + nonce

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('ciphertext')
    client.close()
  })

  it('returns error for message missing toDeviceId', async () => {
    const client = await connectClient(port, token)
    client.send({ type: 'register', userId: 'test-user2', deviceId: 'dev2' })
    await waitForMessage(client, (m) => m['type'] === 'registered')

    client.send({ type: 'message', to: 'someone', ciphertext: 'abc', nonce: 'xyz' }) // missing toDeviceId

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('toDeviceId')
    client.close()
  })

  // ── Presence ────────────────────────────────────────────────────────────────

  it('routes a presence update to an online recipient', async () => {
    const alice = await connectClient(port, token)
    const bob   = await connectClient(port, token)

    alice.send({ type: 'register', userId: 'alice-p', deviceId: 'alice-dev' })
    bob.send({ type: 'register', userId: 'bob-p', deviceId: 'bob-dev' })
    await waitForMessage(alice, (m) => m['type'] === 'registered')
    await waitForMessage(bob,   (m) => m['type'] === 'registered')

    alice.send({
      type:       'presence',
      to:         'bob-p',
      toDeviceId: 'bob-dev',
      ciphertext: 'cHJlc2VuY2VDdA',
      nonce:      'cHJlc2VuY2VOb25jZQ',
      prekey:     { identityKey: 'ik', ephemeralKey: 'ek', signedPreKeyId: 1, oneTimePreKeyId: null },
    })

    const msg = await waitForMessage(bob, (m) => m['type'] === 'presence')
    expect(msg['from']).toBe('alice-p')
    expect(msg['fromDeviceId']).toBe('alice-dev')
    expect(msg['ciphertext']).toBe('cHJlc2VuY2VDdA')
    expect(msg['nonce']).toBe('cHJlc2VuY2VOb25jZQ')
    expect(msg['prekey']).toEqual({ identityKey: 'ik', ephemeralKey: 'ek', signedPreKeyId: 1, oneTimePreKeyId: null })

    alice.close()
    bob.close()
  })

  it('drops a presence update if recipient is offline (no queue)', async () => {
    const alice = await connectClient(port, token)
    alice.send({ type: 'register', userId: 'alice-ghost', deviceId: 'alice-dev' })
    await waitForMessage(alice, (m) => m['type'] === 'registered')

    // Bob is not connected — presence should be silently dropped
    alice.send({
      type:       'presence',
      to:         'bob-ghost',
      toDeviceId: 'bob-dev',
      ciphertext: 'abc',
      nonce:      'xyz',
    })

    // Give server time to process
    await new Promise((r) => setTimeout(r, 100))

    // Bob connects later — should NOT receive any presence update
    const bob = await connectClient(port, token)
    bob.send({ type: 'register', userId: 'bob-ghost', deviceId: 'bob-dev' })
    await waitForMessage(bob, (m) => m['type'] === 'registered')

    await new Promise((r) => setTimeout(r, 100))
    const presenceMsg = bob.received.find((m) => m['type'] === 'presence')
    expect(presenceMsg).toBeUndefined()

    alice.close()
    bob.close()
  })

  it('returns error for presence sent without prior register', async () => {
    const client = await connectClient(port, token)
    client.send({
      type: 'presence', to: 'someone', toDeviceId: 'dev', ciphertext: 'abc', nonce: 'xyz',
    })

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('register')
    client.close()
  })

  it('returns error for presence missing required fields', async () => {
    const client = await connectClient(port, token)
    client.send({ type: 'register', userId: 'test-pres', deviceId: 'dev-pres' })
    await waitForMessage(client, (m) => m['type'] === 'registered')

    client.send({ type: 'presence', to: 'someone' }) // missing toDeviceId, ciphertext, nonce

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('presence requires')
    client.close()
  })
})
