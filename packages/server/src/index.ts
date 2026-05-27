// Copyright 2026 Encra (encra.dev). Licensed under the Business Source License 1.1.
// See LICENSE in this package for terms. Free for non-commercial/non-production use.
// Commercial hosted-service use requires a license from Encra (encra.dev).
import 'dotenv/config'
import http from 'http'
import { createApp } from './app.js'
import { attachWebSocketRelay } from './ws/relay.js'
import { closePool, getPool } from './db/pool.js'
import { closeRedis } from './redis.js'
import { logger } from './logger.js'

const PORT = parseInt(process.env['PORT'] ?? '3000', 10)

// ── Server setup ──────────────────────────────────────────────────────────────

const app    = createApp()
const server = http.createServer(app)
attachWebSocketRelay(server)

server.listen(PORT, () => {
  logger.info({ port: PORT }, 'Encra server listening')
})

// ── Offline-queue cleanup job ─────────────────────────────────────────────────
// Deletes queued messages older than QUEUE_RETENTION_DAYS every 6 hours.
// Uses interval.unref() so it never prevents the process from exiting.

const QUEUE_CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1_000   // 6 hours
const QUEUE_RETENTION_DAYS      = parseInt(process.env['QUEUE_RETENTION_DAYS'] ?? '7', 10)

async function runQueueCleanup(): Promise<void> {
  try {
    const result = await getPool().query(
      `DELETE FROM message_queue WHERE created_at < NOW() - ($1 || ' days')::INTERVAL`,
      [QUEUE_RETENTION_DAYS],
    )
    logger.info({ deleted: result.rowCount, retentionDays: QUEUE_RETENTION_DAYS }, 'Message queue cleanup complete')
  } catch (err) {
    logger.error({ err }, 'Message queue cleanup failed')
  }
}

const cleanupInterval = setInterval(runQueueCleanup, QUEUE_CLEANUP_INTERVAL_MS)
cleanupInterval.unref()   // Don't prevent process exit

// ── Graceful shutdown ─────────────────────────────────────────────────────────

let isShuttingDown = false

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) return
  isShuttingDown = true

  logger.info({ signal }, 'Graceful shutdown initiated')

  // Force-exit if shutdown takes longer than 15 seconds
  const forceExit = setTimeout(() => {
    logger.error('Forced exit — shutdown exceeded 15 s')
    process.exit(1)
  }, 15_000)
  forceExit.unref()

  clearInterval(cleanupInterval)

  // Stop accepting new HTTP/WebSocket connections
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  )
  logger.info('HTTP server closed')

  // Drain the database pool (waits for in-flight queries)
  await closePool()

  // Close Redis connections
  await closeRedis()

  logger.info('Shutdown complete')
  process.exit(0)
}

process.on('SIGTERM', () => { void shutdown('SIGTERM') })
process.on('SIGINT',  () => { void shutdown('SIGINT')  })

// ── Unhandled rejection / exception guard ────────────────────────────────────

process.on('unhandledRejection', (reason, promise) => {
  logger.error({ reason, promise: String(promise) }, 'Unhandled promise rejection — this is a bug')
  // Don't exit — let the error surface in logs for investigation
})

process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'Uncaught exception — shutting down')
  void shutdown('uncaughtException')
})
