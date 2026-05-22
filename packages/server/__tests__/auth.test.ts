import { describe, it, expect, vi, afterEach } from 'vitest'
import request from 'supertest'
import { createApp } from '../src/app.js'
import { setPool, getPool } from '../src/db/pool.js'
import type { Pool, QueryResult } from 'pg'

function makeMockPool(): Pool {
  return {
    query: vi.fn(async () => ({ rows: [], rowCount: 0 } as unknown as QueryResult)),
  } as unknown as Pool
}

describe('auth middleware edge cases', () => {
  afterEach(() => {
    // Restore JWT_SECRET if modified
    process.env['JWT_SECRET'] = 'test-secret-do-not-use-in-production'
  })

  it('returns 500 when JWT_SECRET env var is not set', async () => {
    setPool(makeMockPool())
    delete process.env['JWT_SECRET']
    const app = createApp()

    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', 'Bearer sometoken')
      .send({ userId: 'alice', publicKey: 'key' })

    // Server misconfiguration — results in 500
    expect(res.status).toBe(500)
  })

  it('returns 401 for Bearer token with missing developerId claim', async () => {
    setPool(makeMockPool())
    const jwt = await import('jsonwebtoken')
    // Sign token without developerId field
    const token = jwt.default.sign({ role: 'user' }, 'test-secret-do-not-use-in-production')

    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', `Bearer ${token}`)
      .send({ userId: 'alice', publicKey: 'key' })

    expect(res.status).toBe(401)
  })

  it('returns 500 on unexpected pool error', async () => {
    const pool = {
      query: vi.fn(async () => { throw new Error('DB down') }),
    } as unknown as Pool
    setPool(pool)
    const jwt = await import('jsonwebtoken')
    const token = jwt.default.sign({ developerId: 'dev' }, 'test-secret-do-not-use-in-production')

    const app = createApp()
    const res = await request(app)
      .post('/v1/keys')
      .set('Authorization', `Bearer ${token}`)
      .send({ userId: 'alice', publicKey: 'key' })

    expect(res.status).toBe(500)
  })
})

describe('pool singleton', () => {
  it('getPool returns the pool set by setPool', () => {
    const mock = makeMockPool()
    setPool(mock)
    expect(getPool()).toBe(mock)
  })
})
