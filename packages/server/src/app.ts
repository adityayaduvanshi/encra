import express, { Request, Response, NextFunction } from 'express'
import { HttpError } from './errors.js'
import healthRouter from './routes/health.js'
import keysRouter from './routes/keys.js'

export function createApp(): express.Application {
  const app = express()

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
