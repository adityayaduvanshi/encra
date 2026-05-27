/**
 * Health-check endpoint tests.
 *
 * Covers both the happy path (DB ok → 200) and the failure path (DB down → 503).
 * Redis is not configured in tests, so the redis section always reports
 * { ok: false, enabled: false }.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import request from 'supertest'
import type { Pool, QueryResult } from 'pg'
import { createApp } from '../src/app.js'
import { setPool } from '../src/db/pool.js'

function makeHealthyPool(): Pool {
  return {
    query: vi.fn(async () => ({
      rows:     [{ '?column?': 1 }],
      rowCount: 1,
    } as unknown as QueryResult)),
  } as unknown as Pool
}

function makeUnhealthyPool(): Pool {
  return {
    query: vi.fn().mockRejectedValue(new Error('Connection refused')),
  } as unknown as Pool
}

describe('GET /health', () => {
  beforeEach(() => {
    delete process.env['REDIS_URL']
  })

  it('returns 200 with db.ok:true when database is healthy', async () => {
    setPool(makeHealthyPool())
    const app = createApp()
    const res = await request(app).get('/health')

    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({
      ok:    true,
      db:    { ok: true },
      redis: { ok: false, enabled: false },
    })
    expect(typeof res.body.uptime).toBe('number')
    expect(typeof res.body.db.latencyMs).toBe('number')
  })

  it('returns 503 with db.ok:false when database is unavailable', async () => {
    setPool(makeUnhealthyPool())
    const app = createApp()
    const res = await request(app).get('/health')

    expect(res.status).toBe(503)
    expect(res.body).toMatchObject({
      ok: false,
      db: { ok: false, latencyMs: null },
    })
  })
})
