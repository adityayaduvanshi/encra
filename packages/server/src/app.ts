import express, { Request, Response, NextFunction } from 'express'
import { HttpError } from './errors.js'
import healthRouter from './routes/health.js'
import keysRouter from './routes/keys.js'

const ALLOWED_ORIGINS = (process.env['ALLOWED_ORIGINS'] ?? '*').split(',').map(s => s.trim())

export function createApp(): express.Application {
  const app = express()

  // CORS — allow dashboard and any developer app to call the key server
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

  app.use(express.json())

  app.use(healthRouter)
  app.use(keysRouter)

  // Global error handler
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) {
      res.status(err.statusCode).json({ error: err.message })
      return
    }
    console.error(err)
    res.status(500).json({ error: 'Internal server error.' })
  })

  return app
}
