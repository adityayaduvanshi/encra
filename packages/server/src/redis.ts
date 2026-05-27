import Redis from 'ioredis'
import { logger } from './logger.js'

/**
 * Optional Redis pub/sub for horizontal WebSocket relay scaling.
 *
 * When REDIS_URL is set, the relay publishes outbound messages to Redis so
 * that recipient sockets connected to *other* server instances receive them.
 *
 * When REDIS_URL is not set (default), everything runs in single-instance mode
 * with no external dependencies — zero behaviour change for self-hosters.
 *
 * Two separate ioredis clients are created (pub and sub) because a client in
 * subscriber mode cannot issue commands other than SUBSCRIBE / PSUBSCRIBE.
 */

let _publisher:  Redis | null = null
let _subscriber: Redis | null = null

function makeClient(url: string, role: 'publisher' | 'subscriber'): Redis {
  const client = new Redis(url, {
    maxRetriesPerRequest:  3,
    // Disable the INFO-based ready check — many managed Redis services
    // (Upstash, Redis Cloud) restrict the INFO command.
    enableReadyCheck:      false,
    lazyConnect:           true,
    retryStrategy: (times) => Math.min(times * 200, 5_000),
  })

  client.on('error', (err: Error) => {
    logger.warn({ err: err.message, role }, 'Redis connection error')
  })
  client.on('connect', () => {
    logger.info({ role }, 'Redis connected')
  })
  client.on('reconnecting', () => {
    logger.info({ role }, 'Redis reconnecting…')
  })

  return client
}

/**
 * Returns the publisher client, or `null` when REDIS_URL is not configured.
 * Lazily creates and connects on first call.
 */
export function getPublisher(): Redis | null {
  const url = process.env['REDIS_URL']
  if (!url) return null
  if (!_publisher) {
    _publisher = makeClient(url, 'publisher')
    _publisher.connect().catch((err: Error) => {
      logger.warn({ err: err.message }, 'Redis publisher failed to connect — running in single-instance mode')
      _publisher = null
    })
  }
  return _publisher
}

/**
 * Returns the subscriber client, or `null` when REDIS_URL is not configured.
 * Lazily creates and connects on first call.
 */
export function getSubscriber(): Redis | null {
  const url = process.env['REDIS_URL']
  if (!url) return null
  if (!_subscriber) {
    _subscriber = makeClient(url, 'subscriber')
    _subscriber.connect().catch((err: Error) => {
      logger.warn({ err: err.message }, 'Redis subscriber failed to connect — running in single-instance mode')
      _subscriber = null
    })
  }
  return _subscriber
}

/**
 * Gracefully close both Redis connections.
 * Called during graceful shutdown.
 */
export async function closeRedis(): Promise<void> {
  const tasks: Promise<void>[] = []
  if (_publisher)  tasks.push(_publisher.quit().then(() => { _publisher  = null }))
  if (_subscriber) tasks.push(_subscriber.quit().then(() => { _subscriber = null }))
  await Promise.allSettled(tasks)
}
