import express, { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import pinoHttp from 'pino-http'
import { HttpError } from './errors.js'
import { logger } from './logger.js'
import { globalLimiter, keyRegistrationLimiter } from './middleware/rateLimiter.js'
import healthRouter from './routes/health.js'
import keysRouter from './routes/keys.js'

const ALLOWED_ORIGINS = (process.env['ALLOWED_ORIGINS'] ?? '*').split(',').map(s => s.trim())

export function createApp(): express.Application {
  const app = express()

  // ── Security headers ────────────────────────────────────────────────────────
  // helmet sets sensible defaults (HSTS, X-Frame-Options, etc.). Disable
  // contentSecurityPolicy so it doesn't interfere with any frontend served
  // alongside the API; enable the rest.
  app.use(helmet({ contentSecurityPolicy: false }))

  // ── Request logging ─────────────────────────────────────────────────────────
  // Skip in test environment to keep test output clean.
  if (process.env['NODE_ENV'] !== 'test') {
    app.use(pinoHttp({
      logger,
      // Don't log health checks — they're noisy and uninteresting
      autoLogging: {
        ignore: (req) => req.url === '/health',
      },
      customLogLevel: (_req, res) => {
        if (res.statusCode >= 500) return 'error'
        if (res.statusCode >= 400) return 'warn'
        return 'info'
      },
    }))
  }

  // ── CORS ────────────────────────────────────────────────────────────────────
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers['origin'] ?? ''
    if (ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*')
    } else {
      res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0] ?? '*')
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
    res.setHeader('Access-Control-Max-Age', '86400')
    if (req.method === 'OPTIONS') { res.sendStatus(204); return }
    next()
  })

  // ── Body parsing (64 KB limit — generous for key registration, strict enough
  //    to prevent payload flooding) ───────────────────────────────────────────
  app.use(express.json({ limit: '64kb' }))

  // ── Rate limiting ────────────────────────────────────────────────────────────
  app.use(globalLimiter)
  app.use('/v1/keys', keyRegistrationLimiter)

  // ── Routes ───────────────────────────────────────────────────────────────────
  app.use(healthRouter)
  app.use(keysRouter)

  // ── Global error handler ─────────────────────────────────────────────────────
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) {
      res.status(err.statusCode).json({ error: err.message })
      return
    }
    logger.error({ err }, 'Unhandled Express error')
    res.status(500).json({ error: 'Internal server error.' })
  })

  return app
}
