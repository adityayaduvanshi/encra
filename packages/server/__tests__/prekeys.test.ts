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

interface OtpRow { id: number; user_id: string; device_id: string; key_id: number; public_key: string }

/**
 * Stateful in-memory pool modelling the X3DH prekey tables:
 *   identity_keys    (user_id, device_id) -> identity_key
 *   signed_prekeys   (user_id, device_id) -> { key_id, public_key, signature }
 *   one_time_prekeys list of rows, consumed FIFO on DELETE ... RETURNING
 */
function makeMockPool() {
  const identity = new Map<string, string>()
  const signed   = new Map<string, { key_id: number; public_key: string; signature: string }>()
  const otps: OtpRow[] = []
  let nextId = 1

  const key = (u: string, d: string) => `${u}::${d}`

  const query = vi.fn(async (sql: string, params: unknown[] = []) => {
      const s = sql.trim().toUpperCase().replace(/\s+/g, ' ')

      // Transaction control statements are no-ops against the in-memory store.
      if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') {
        return { rows: [], rowCount: 0 } as unknown as QueryResult
      }

      if (s === 'SELECT 1') return { rows: [{ '?column?': 1 }], rowCount: 1 } as unknown as QueryResult

      if (s.startsWith('INSERT INTO IDENTITY_KEYS')) {
        identity.set(key(params[0] as string, params[1] as string), params[2] as string)
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      if (s.startsWith('INSERT INTO SIGNED_PREKEYS')) {
        signed.set(key(params[0] as string, params[1] as string), {
          key_id: params[2] as number, public_key: params[3] as string, signature: params[4] as string,
        })
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      if (s.startsWith('INSERT INTO ONE_TIME_PREKEYS')) {
        const [u, d, kid, pk] = [params[0] as string, params[1] as string, params[2] as number, params[3] as string]
        if (!otps.some((o) => o.user_id === u && o.device_id === d && o.key_id === kid)) {
          otps.push({ id: nextId++, user_id: u, device_id: d, key_id: kid, public_key: pk })
        }
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }

      if (s.startsWith('SELECT COUNT(*)')) {
        const [u, d] = [params[0] as string, params[1] as string]
        const count = otps.filter((o) => o.user_id === u && o.device_id === d).length
        return { rows: [{ count: String(count) }], rowCount: 1 } as unknown as QueryResult
      }

      if (s.startsWith('SELECT IDENTITY_KEY FROM IDENTITY_KEYS')) {
        const ik = identity.get(key(params[0] as string, params[1] as string))
        return ik
          ? { rows: [{ identity_key: ik }], rowCount: 1 } as unknown as QueryResult
          : { rows: [], rowCount: 0 } as unknown as QueryResult
      }

      if (s.startsWith('SELECT KEY_ID, PUBLIC_KEY, SIGNATURE FROM SIGNED_PREKEYS')) {
        const sp = signed.get(key(params[0] as string, params[1] as string))
        return sp
          ? { rows: [sp], rowCount: 1 } as unknown as QueryResult
          : { rows: [], rowCount: 0 } as unknown as QueryResult
      }

      if (s.startsWith('DELETE FROM ONE_TIME_PREKEYS')) {
        const [u, d] = [params[0] as string, params[1] as string]
        const idx = otps.findIndex((o) => o.user_id === u && o.device_id === d)
        if (idx === -1) return { rows: [], rowCount: 0 } as unknown as QueryResult
        const [row] = otps.splice(idx, 1)
        return { rows: [{ key_id: row!.key_id, public_key: row!.public_key }], rowCount: 1 } as unknown as QueryResult
      }

      return { rows: [], rowCount: 0 } as unknown as QueryResult
    })

  const pool = {
    query,
    // POST /v1/prekeys runs its writes in a transaction via a dedicated client;
    // the client shares the same in-memory query handler and a no-op release.
    connect: vi.fn(async () => ({ query, release: vi.fn() })),
  } as unknown as Pool

  return { pool, identity, signed, otps }
}

const VALID_BODY = {
  userId: 'alice',
  deviceId: 'laptop',
  identityKey: 'aWRlbnRpdHlfa2V5X2Jhc2U2NA',
  signedPreKey: { keyId: 1, publicKey: 'c2lnbmVkX3ByZWtleQ', signature: 'c2lnbmF0dXJl' },
  oneTimePreKeys: [
    { keyId: 1, publicKey: 'b3RwX29uZQ' },
    { keyId: 2, publicKey: 'b3RwX3R3bw' },
  ],
}

describe('POST /v1/prekeys', () => {
  beforeEach(() => {
    process.env['JWT_SECRET'] = JWT_SECRET
  })

  it('publishes a bundle and reports the one-time prekey count', async () => {
    setPool(makeMockPool().pool)
    const app = createApp()
    const res = await request(app)
      .post('/v1/prekeys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send(VALID_BODY)

    expect(res.status).toBe(201)
    expect(res.body).toMatchObject({ userId: 'alice', deviceId: 'laptop', oneTimePreKeyCount: 2 })
  })

  it('works with no one-time prekeys', async () => {
    setPool(makeMockPool().pool)
    const app = createApp()
    const res = await request(app)
      .post('/v1/prekeys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ ...VALID_BODY, oneTimePreKeys: [] })

    expect(res.status).toBe(201)
    expect(res.body.oneTimePreKeyCount).toBe(0)
  })

  it('returns 401 without a token', async () => {
    setPool(makeMockPool().pool)
    const app = createApp()
    const res = await request(app).post('/v1/prekeys').send(VALID_BODY)
    expect(res.status).toBe(401)
  })

  it('returns 400 when identityKey is missing', async () => {
    setPool(makeMockPool().pool)
    const app = createApp()
    const { identityKey, ...rest } = VALID_BODY
    void identityKey
    const res = await request(app)
      .post('/v1/prekeys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send(rest)
    expect(res.status).toBe(400)
  })

  it('returns 400 when signedPreKey is malformed', async () => {
    setPool(makeMockPool().pool)
    const app = createApp()
    const res = await request(app)
      .post('/v1/prekeys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send({ ...VALID_BODY, signedPreKey: { keyId: 'nope', publicKey: 'x', signature: 'y' } })
    expect(res.status).toBe(400)
  })
})

describe('GET /v1/prekeys/:userId/:deviceId', () => {
  beforeEach(() => {
    process.env['JWT_SECRET'] = JWT_SECRET
  })

  async function seed(pool: Pool) {
    const app = createApp()
    await request(app)
      .post('/v1/prekeys')
      .set('Authorization', `Bearer ${makeToken()}`)
      .send(VALID_BODY)
    return app
    void pool
  }

  it('returns a bundle and consumes one one-time prekey', async () => {
    const mock = makeMockPool()
    setPool(mock.pool)
    const app = await seed(mock.pool)

    const res = await request(app)
      .get('/v1/prekeys/alice/laptop')
      .set('Authorization', `Bearer ${makeToken()}`)

    expect(res.status).toBe(200)
    expect(res.body.identityKey).toBe(VALID_BODY.identityKey)
    expect(res.body.signedPreKey).toMatchObject({ keyId: 1 })
    expect(res.body.oneTimePreKey).toBeDefined()
    // pool went from 2 -> 1
    expect(mock.otps).toHaveLength(1)
  })

  it('omits the one-time prekey once the pool is exhausted', async () => {
    const mock = makeMockPool()
    setPool(mock.pool)
    const app = await seed(mock.pool)

    // consume both
    await request(app).get('/v1/prekeys/alice/laptop').set('Authorization', `Bearer ${makeToken()}`)
    await request(app).get('/v1/prekeys/alice/laptop').set('Authorization', `Bearer ${makeToken()}`)
    // third fetch — pool empty
    const res = await request(app)
      .get('/v1/prekeys/alice/laptop')
      .set('Authorization', `Bearer ${makeToken()}`)

    expect(res.status).toBe(200)
    expect(res.body.oneTimePreKey).toBeUndefined()
  })

  it('returns 404 for a device with no published prekeys', async () => {
    setPool(makeMockPool().pool)
    const app = createApp()
    const res = await request(app)
      .get('/v1/prekeys/nobody/somedevice')
      .set('Authorization', `Bearer ${makeToken()}`)
    expect(res.status).toBe(404)
  })

  it('does not consume a one-time prekey when consumeOneTime=false (presence sessions)', async () => {
    const mock = makeMockPool()
    setPool(mock.pool)
    const app = await seed(mock.pool)

    const res = await request(app)
      .get('/v1/prekeys/alice/laptop?consumeOneTime=false')
      .set('Authorization', `Bearer ${makeToken()}`)

    expect(res.status).toBe(200)
    expect(res.body.identityKey).toBe(VALID_BODY.identityKey)
    expect(res.body.signedPreKey).toMatchObject({ keyId: 1 })
    // No OTP returned and the pool is untouched (still 2).
    expect(res.body.oneTimePreKey).toBeUndefined()
    expect(mock.otps).toHaveLength(2)
  })

  it('hands out distinct one-time prekeys to concurrent fetchers', async () => {
    const mock = makeMockPool()
    setPool(mock.pool)
    const app = await seed(mock.pool)

    const [a, b] = await Promise.all([
      request(app).get('/v1/prekeys/alice/laptop').set('Authorization', `Bearer ${makeToken()}`),
      request(app).get('/v1/prekeys/alice/laptop').set('Authorization', `Bearer ${makeToken()}`),
    ])
    expect(a.body.oneTimePreKey.keyId).not.toBe(b.body.oneTimePreKey.keyId)
  })
})

describe('GET /v1/prekeys/:userId/:deviceId/count', () => {
  beforeEach(() => {
    process.env['JWT_SECRET'] = JWT_SECRET
  })

  it('reports the remaining one-time prekey count', async () => {
    const mock = makeMockPool()
    setPool(mock.pool)
    const app = createApp()
    await request(app).post('/v1/prekeys').set('Authorization', `Bearer ${makeToken()}`).send(VALID_BODY)

    const res = await request(app)
      .get('/v1/prekeys/alice/laptop/count')
      .set('Authorization', `Bearer ${makeToken()}`)
    expect(res.status).toBe(200)
    expect(res.body.oneTimePreKeyCount).toBe(2)
  })
})
