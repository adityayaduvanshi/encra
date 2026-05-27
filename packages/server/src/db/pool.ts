import { Pool } from 'pg'
import { logger } from '../logger.js'

let _pool: Pool | null = null

/**
 * Returns the singleton PostgreSQL connection pool.
 *
 * Pool settings are tuned for a production workload:
 *   - min 2 connections kept warm to avoid cold-start latency
 *   - max 20 connections (tune via DB_POOL_MAX env var for larger deployments)
 *   - 30s idle timeout — reclaims connections that aren't being used
 *   - 5s connection timeout — fast failure rather than hanging indefinitely
 *   - 10s statement timeout — kills runaway queries before they block the pool
 */
export function getPool(): Pool {
  if (!_pool) {
    _pool = new Pool({
      connectionString:       process.env['DATABASE_URL'],
      min:                    2,
      max:                    parseInt(process.env['DB_POOL_MAX'] ?? '20', 10),
      idleTimeoutMillis:      30_000,
      connectionTimeoutMillis: 5_000,
      statement_timeout:      10_000,   // per-query hard timeout (ms)
    })

    _pool.on('error', (err) => {
      // Log unexpected idle-client errors — these are non-fatal but worth knowing about
      logger.error({ err: err.message }, 'Unexpected PostgreSQL pool error')
    })

    _pool.on('connect', () => {
      logger.debug('PostgreSQL new client acquired')
    })
  }
  return _pool
}

/**
 * Replaces the pool singleton — used in tests to inject a mock.
 */
export function setPool(pool: Pool): void {
  _pool = pool
}

/**
 * Gracefully drains and closes the pool.
 * Called during graceful shutdown — waits for all in-flight queries to finish.
 */
export async function closePool(): Promise<void> {
  if (_pool) {
    await _pool.end()
    _pool = null
    logger.info('PostgreSQL pool closed')
  }
}
