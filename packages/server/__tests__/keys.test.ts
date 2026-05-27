import { describe, it, expect, beforeEach, vi } from 'vitest'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import { createApp } from '../src/app.js'
import { setPool } from '../src/db/pool.js'
import type { Pool, QueryResult } from 'pg'

const JWT_SECRET = 'test-secret-do-not-use-in-production'

function makeToken(): string {
  return jwt.sign({ developerId: 'test-dev' }, JWT_SECRET, { expiresIn: '1h' })
}

/**
 * In-memory mock pool that mirrors the multi-device schema:
 *   public_keys (user_id, device_id, public_key)
 *
 * INSERT params: [$1=userId, $2=deviceId, $3=publicKey]
 * SELECT params: [$1=userId]  → returns rows with { device_id, public_key }
 * SELECT 1:      health check — always succeeds
 */
function makeMockPool(store: Map<string, { deviceId: string; publicKey: string }[]>): Pool {
  return {
    query: vi.fn(async (sql: string, params: unknown[]) => {
      const s = sql.trim().toUpperCase().replace(/\s+/g, ' ')

      // Health-check ping
      if (s === 'SELECT 1') {
        return { rows: [{ '?column?': 1 }], rowCount: 1 } as unknown as QueryResult
      }

      // INSERT INTO public_keys (user_id, device_id, public_key) VALUES ($1, $2, $3)
      if (s.startsWith('INSERT INTO PUBLIC_KEYS')) {
        const userId   = params[0] as string
        const deviceId = params[1] as string
        const pubKey   = params[2] as string
        const existing = store.get(userId) ?? []
        const idx = existing.findIndex((d) => d.deviceId === deviceId)
        if (idx >= 0) existing[idx] = { deviceId, publicKey: pubKey }
        else          existing.push({ deviceId, publicKey: pubKey })
        store.set(userId, existing)
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      // SELECT device_id, public_key FROM public_keys WHERE user_id = $1
      if (s.startsWith('SELECT DEVICE_ID, PUBLIC_KEY FROM PUBLIC_KEYS')) {
        const userId  = params[0] as string
        const devices = store.get(userId)
        if (devices?.length) {
          return {
            rows:     devices.map((d) => ({ device_id: d.deviceId, public_key: d.publicKey })),
            rowCount: devices.length,
          } as unknown as QueryResult
        }
        return { rows: [], rowCount: 0 } as unknown as QueryResult
      }

      return { rows: [], rowCount: 0 } as unknown as QueryResult
    }),
  } as unknown as Pool
}

// ── POST /v1/keys ─────────────────────────────────────────────────────────────

describe('POST /v1/keys', () => {
  let store: Map<string, { deviceId: string; publicKey: string }[]>

  beforeEach(() => {
    store = new Map()
    process.env['JWT_SECRET'] = JWT_SECRET
    setPool(makeMockPool(store))
  })

  it('returns 201 with userId and deviceId on valid registration', async () => {
    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ userId: 'alice', publicKey: 'VSKR8CyTF1GWMwITAtD3ujmxzzIxDiPueqakMSrkoCc' })

    expect(res.status).toBe(201)
    expect(res.body).toMatchObject({ userId: 'alice', deviceId: 'default' })
    expect(store.get('alice')).toEqual([
      { deviceId: 'default', publicKey: 'VSKR8CyTF1GWMwITAtD3ujmxzzIxDiPueqakMSrkoCc' },
    ])
  })

  it('returns 201 with explicit deviceId', async () => {
    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ userId: 'alice', deviceId: 'my-device-uuid', publicKey: 'VSKR8CyTF1GWMwITAtD3ujmxzzIxDiPueqakMSrkoCc' })

    expect(res.status).toBe(201)
    expect(res.body).toEqual({ userId: 'alice', deviceId: 'my-device-uuid' })
  })

  it('returns 401 without Authorization header', async () => {
    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .send({ userId: 'alice', publicKey: 'somekey' })

    expect(res.status).toBe(401)
  })

  it('returns 401 with invalid token', async () => {
    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', 'Bearer invalid.token.here')
      .send({ userId: 'alice', publicKey: 'somekey' })

    expect(res.status).toBe(401)
  })

  it('returns 400 when userId is missing', async () => {
    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ publicKey: 'somekey' })

    expect(res.status).toBe(400)
  })

  it('returns 400 when publicKey is missing', async () => {
    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ userId: 'alice' })

    expect(res.status).toBe(400)
  })
})

// ── GET /v1/keys/:userId ──────────────────────────────────────────────────────

describe('GET /v1/keys/:userId', () => {
  let store: Map<string, { deviceId: string; publicKey: string }[]>

  beforeEach(() => {
    store = new Map()
    store.set('bob', [
      { deviceId: 'laptop', publicKey: 'iLfQ_rHb3Jze-iqBRQPuK75UaOF6PQBo5Pgjvy-U0UI' },
    ])
    process.env['JWT_SECRET'] = JWT_SECRET
    setPool(makeMockPool(store))
  })

  it('returns 200 with devices array for a registered user', async () => {
    const app = createApp()
    const res = await request(app)
      .get('/v1/keys/bob')
      .set('Authorization', `Bearer ${makeToken()}`)

    expect(res.status).toBe(200)
    expect(res.body).toEqual({
      userId:  'bob',
      devices: [{ deviceId: 'laptop', publicKey: 'iLfQ_rHb3Jze-iqBRQPuK75UaOF6PQBo5Pgjvy-U0UI' }],
    })
  })

  it('returns all devices when user has multiple registered devices', async () => {
    store.set('carol', [
      { deviceId: 'phone',  publicKey: 'phonePublicKey123' },
      { deviceId: 'laptop', publicKey: 'laptopPublicKey456' },
    ])
    const app = createApp()
    const res = await request(app)
      .get('/v1/keys/carol')
      .set('Authorization', `Bearer ${makeToken()}`)

    expect(res.status).toBe(200)
    expect(res.body.devices).toHaveLength(2)
  })

  it('returns 404 for an unregistered user', async () => {
    const app = createApp()
    const res = await request(app)
      .get('/v1/keys/nobody')
      .set('Authorization', `Bearer ${makeToken()}`)

    expect(res.status).toBe(404)
    expect(res.body.error).toContain('nobody')
  })

  it('returns 401 without token', async () => {
    const app = createApp()
    const res = await request(app).get('/v1/keys/bob')
    expect(res.status).toBe(401)
  })
})

// ── GET /health ───────────────────────────────────────────────────────────────

describe('GET /health', () => {
  beforeEach(() => {
    // health endpoint pings the DB with SELECT 1 — mock pool handles it
    const store = new Map<string, { deviceId: string; publicKey: string }[]>()
    setPool(makeMockPool(store))
  })

  it('returns 200 with ok:true and db status', async () => {
    process.env['JWT_SECRET'] = JWT_SECRET
    const app = createApp()
    const res = await request(app).get('/health')
    expect(res.status).toBe(200)
    expect(res.body.ok).toBe(true)
    expect(res.body.db.ok).toBe(true)
    expect(typeof res.body.uptime).toBe('number')
  })
})
