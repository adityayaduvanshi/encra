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

function makePool(): { pool: Pool; keys: Map<string, string>; queue: Array<{ recipient_id: string; sender_id: string; ciphertext: string; nonce: string; id: number }> } {
  const keys = new Map<string, string>()
  const queue: Array<{ recipient_id: string; sender_id: string; ciphertext: string; nonce: string; id: number }> = []
  let nextId = 1

  const pool = {
    query: vi.fn(async (sql: string, params: unknown[]) => {
      const s = sql.trim().toUpperCase()

      if (s.startsWith('INSERT INTO PUBLIC_KEYS')) {
        keys.set(params[0] as string, params[1] as string)
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      if (s.startsWith('SELECT USER_ID, PUBLIC_KEY FROM PUBLIC_KEYS')) {
        const key = keys.get(params[0] as string)
        return key
          ? { rows: [{ user_id: params[0], public_key: key }], rowCount: 1 } as unknown as QueryResult
          : { rows: [], rowCount: 0 } as unknown as QueryResult
      }

      if (s.startsWith('INSERT INTO MESSAGE_QUEUE')) {
        const id = nextId++
        queue.push({ recipient_id: params[0] as string, sender_id: params[1] as string, ciphertext: params[2] as string, nonce: params[3] as string, id })
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      if (s.startsWith('DELETE FROM MESSAGE_QUEUE')) {
        const recipientId = params[0] as string
        const pending = queue.filter((m) => m.recipient_id === recipientId)
        const remaining = queue.filter((m) => m.recipient_id !== recipientId)
        queue.length = 0
        queue.push(...remaining)
        return { rows: pending.map((m) => ({ id: m.id, sender_id: m.sender_id, ciphertext: m.ciphertext, nonce: m.nonce })), rowCount: pending.length } as unknown as QueryResult
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
  ws: WebSocket
  received: Array<Record<string, unknown>>
  send: (msg: Record<string, unknown>) => void
  close: () => void
}

function connectClient(port: number, token: string): Promise<WsClient> {
  return new Promise((resolve, reject) => {
    const received: Array<Record<string, unknown>> = []
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/relay?token=${encodeURIComponent(token)}`)

    ws.on('error', reject)
    ws.on('open', () => {
      resolve({
        ws,
        received,
        send: (msg) => ws.send(JSON.stringify(msg)),
        close: () => ws.close(),
      })
    })
    ws.on('message', (raw) => {
      received.push(JSON.parse(raw.toString()) as Record<string, unknown>)
    })
  })
}

function waitForMessage(
  client: WsClient,
  predicate: (msg: Record<string, unknown>) => boolean,
  timeoutMs = 2000
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error('Timeout waiting for message')), timeoutMs)
    const check = setInterval(() => {
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
  let port: number
  let token: string

  beforeEach(async () => {
    const db = makePool()
    setPool(db.pool)
    token = makeToken()
    const started = await startServer()
    server = started.server
    port = started.port
  })

  afterEach(async () => {
    await stopServer(server)
  })

  it('rejects connection without a valid token', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/relay?token=bad.token.here`)
    const closeCode = await new Promise<number>((resolve) => {
      ws.on('close', (code) => resolve(code))
      ws.on('error', () => resolve(4001))
    })
    expect(closeCode).toBe(4001)
  })

  it('server sends registered confirmation after register message', async () => {
    const alice = await connectClient(port, token)
    alice.send({ type: 'register', userId: 'alice' })

    const msg = await waitForMessage(alice, (m) => m['type'] === 'registered')
    expect(msg['userId']).toBe('alice')
    alice.close()
  })

  it('Alice sends a message and Bob receives it in real time', async () => {
    const alice = await connectClient(port, token)
    const bob = await connectClient(port, token)

    alice.send({ type: 'register', userId: 'alice-relay' })
    bob.send({ type: 'register', userId: 'bob-relay' })

    await waitForMessage(alice, (m) => m['type'] === 'registered')
    await waitForMessage(bob, (m) => m['type'] === 'registered')

    alice.send({
      type: 'message',
      to: 'bob-relay',
      ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0',
      nonce: 'dGVzdC1ub25jZQ',
    })

    const received = await waitForMessage(bob, (m) => m['type'] === 'message')
    expect(received['from']).toBe('alice-relay')
    expect(received['ciphertext']).toBe('dGVzdC1jaXBoZXJ0ZXh0')
    expect(received['nonce']).toBe('dGVzdC1ub25jZQ')

    alice.close()
    bob.close()
  })

  it('message is queued when recipient is offline and delivered when they connect', async () => {
    const alice = await connectClient(port, token)
    alice.send({ type: 'register', userId: 'alice-queue' })
    await waitForMessage(alice, (m) => m['type'] === 'registered')

    // Bob is not connected — message should be queued
    alice.send({
      type: 'message',
      to: 'bob-queue',
      ciphertext: 'cXVldWVkLW1lc3NhZ2U',
      nonce: 'cXVldWVkLW5vbmNl',
    })

    // Give the server a moment to process the queue insert
    await new Promise((r) => setTimeout(r, 100))

    // Bob connects and registers — queued message should be flushed
    const bob = await connectClient(port, token)
    bob.send({ type: 'register', userId: 'bob-queue' })

    const queued = await waitForMessage(bob, (m) => m['type'] === 'message')
    expect(queued['from']).toBe('alice-queue')
    expect(queued['ciphertext']).toBe('cXVldWVkLW1lc3NhZ2U')

    alice.close()
    bob.close()
  })

  it('returns error for message sent without prior register', async () => {
    const client = await connectClient(port, token)
    client.send({ type: 'message', to: 'someone', ciphertext: 'abc', nonce: 'xyz' })

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
    client.send({ type: 'register', userId: 'test-user' })
    await waitForMessage(client, (m) => m['type'] === 'registered')

    client.send({ type: 'message', to: 'someone' }) // missing ciphertext + nonce

    const err = await waitForMessage(client, (m) => m['type'] === 'error')
    expect(err['message']).toContain('ciphertext')
    client.close()
  })
})
