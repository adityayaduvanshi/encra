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

function makeMockPool(store: Map<string, string>): Pool {
  return {
    query: vi.fn(async (sql: string, params: unknown[]) => {
      const s = sql.trim().toUpperCase()

      if (s.startsWith('INSERT INTO PUBLIC_KEYS')) {
        const userId = params[0] as string
        const publicKey = params[1] as string
        store.set(userId, publicKey)
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      if (s.startsWith('SELECT USER_ID, PUBLIC_KEY FROM PUBLIC_KEYS')) {
        const userId = params[0] as string
        const key = store.get(userId)
        if (key) {
          return { rows: [{ user_id: userId, public_key: key }], rowCount: 1 } as unknown as QueryResult
        }
        return { rows: [], rowCount: 0 } as unknown as QueryResult
      }

      return { rows: [], rowCount: 0 } as unknown as QueryResult
    }),
  } as unknown as Pool
}

describe('POST /v1/keys', () => {
  let store: Map<string, string>

  beforeEach(() => {
    store = new Map()
    setPool(makeMockPool(store))
  })

  it('returns 201 and userId on valid registration', async () => {
    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ userId: 'alice', publicKey: 'VSKR8CyTF1GWMwITAtD3ujmxzzIxDiPueqakMSrkoCc' })

    expect(res.status).toBe(201)
    expect(res.body).toEqual({ userId: 'alice' })
    expect(store.get('alice')).toBe('VSKR8CyTF1GWMwITAtD3ujmxzzIxDiPueqakMSrkoCc')
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

describe('GET /v1/keys/:userId', () => {
  let store: Map<string, string>

  beforeEach(() => {
    store = new Map()
    store.set('bob', 'iLfQ_rHb3Jze-iqBRQPuK75UaOF6PQBo5Pgjvy-U0UI')
    setPool(makeMockPool(store))
  })

  it('returns 200 and the public key for a registered user', async () => {
    const app = createApp()
    const res = await request(app)
      .get('/v1/keys/bob')
      .set('Authorization', `Bearer ${makeToken()}`)

    expect(res.status).toBe(200)
    expect(res.body).toEqual({
      userId: 'bob',
      publicKey: 'iLfQ_rHb3Jze-iqBRQPuK75UaOF6PQBo5Pgjvy-U0UI',
    })
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

describe('GET /health', () => {
  it('returns 200 { ok: true }', async () => {
    const app = createApp()
    const res = await request(app).get('/health')
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ ok: true })
  })
})
