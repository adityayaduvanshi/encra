import { Router, Request, Response } from 'express'
import { getPool } from '../db/pool.js'
import { getPublisher } from '../redis.js'

const router = Router()

interface HealthResponse {
  ok:      boolean
  uptime:  number                                          // process uptime in seconds
  db:      { ok: boolean; latencyMs: number | null }
  redis:   { ok: boolean; enabled: boolean }
}

/**
 * GET /health
 *
 * Liveness + readiness check.
 * - Pings PostgreSQL with SELECT 1 and reports latency
 * - Pings Redis (when enabled) and reports status
 * - Returns HTTP 200 when healthy, 503 when the database is unreachable
 *
 * The relay and background jobs depend on PostgreSQL — a DB failure makes
 * the server effectively non-functional, so we signal that with 503 so that
 * load balancers can remove the instance from rotation.
 */
router.get('/health', async (_req: Request, res: Response) => {
  const health: HealthResponse = {
    ok:     true,
    uptime: Math.floor(process.uptime()),
    db:     { ok: false, latencyMs: null },
    redis:  { ok: false, enabled: Boolean(process.env['REDIS_URL']) },
  }

  // ── Database check ──────────────────────────────────────────────────────────
  try {
    const start = Date.now()
    await getPool().query('SELECT 1')
    health.db = { ok: true, latencyMs: Date.now() - start }
  } catch {
    health.ok = false
    health.db = { ok: false, latencyMs: null }
  }

  // ── Redis check (optional) ──────────────────────────────────────────────────
  const pub = getPublisher()
  if (pub) {
    try {
      await pub.ping()
      health.redis = { ok: true, enabled: true }
    } catch {
      health.redis = { ok: false, enabled: true }
      // Redis failure is non-fatal (falls back to single-instance mode)
    }
  }

  res.status(health.ok ? 200 : 503).json(health)
})

export default router
