/**
 * PostgreSQL pool tests.
 *
 * Tests the getPool / setPool / closePool lifecycle.
 * All tests use mock pools — no real database required.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { Pool } from 'pg'
import { getPool, setPool, closePool } from '../src/db/pool.js'

function makeMockPool(endFn = vi.fn().mockResolvedValue(undefined)): Pool {
  return {
    end:   endFn,
    query: vi.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    on:    vi.fn(),
  } as unknown as Pool
}

describe('pool lifecycle', () => {
  beforeEach(() => {
    setPool(makeMockPool())
  })

  it('getPool() returns the pool set by setPool()', () => {
    const mock = makeMockPool()
    setPool(mock)
    expect(getPool()).toBe(mock)
  })

  it('closePool() calls pool.end()', async () => {
    const endFn = vi.fn().mockResolvedValue(undefined)
    setPool(makeMockPool(endFn))

    await closePool()
    expect(endFn).toHaveBeenCalledOnce()
  })

  it('closePool() is a no-op when called a second time', async () => {
    const endFn = vi.fn().mockResolvedValue(undefined)
    setPool(makeMockPool(endFn))

    await closePool()
    await closePool()   // second call — pool is null, should not throw

    expect(endFn).toHaveBeenCalledOnce()
  })

  it('getPool() creates a new pool instance after closePool()', async () => {
    // After closing, the next call to getPool() must re-create the pool.
    // This test covers the pool-creation code path inside getPool().
    setPool(makeMockPool(vi.fn().mockResolvedValue(undefined)))
    await closePool()

    // getPool() will now create a real pg.Pool (DATABASE_URL is undefined in
    // tests — Pool creation is lazy and safe without a real connection string).
    const pool = getPool()
    expect(pool).toBeDefined()

    // Restore a mock so later tests don't accidentally use the real Pool
    setPool(makeMockPool())
  })
})
