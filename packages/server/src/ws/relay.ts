import { WebSocketServer, WebSocket } from 'ws'
import { IncomingMessage, Server } from 'http'
import jwt from 'jsonwebtoken'
import { getPool } from '../db/pool.js'
import { getPublisher, getSubscriber } from '../redis.js'
import { logger } from '../logger.js'

// ── Constants ───────────────────────────────────────────────────────────────

/** Maximum JSON payload size for a single WebSocket message (64 KB). */
const MAX_MESSAGE_BYTES = 64 * 1024

/**
 * Max simultaneous WebSocket connections per process.
 * Tune via MAX_WS_CONNECTIONS env var for larger deployments.
 */
const MAX_CONNECTIONS = parseInt(process.env['MAX_WS_CONNECTIONS'] ?? '10000', 10)

/** How often to send a WebSocket ping to check if the client is still alive. */
const HEARTBEAT_INTERVAL_MS = 30_000

/** How long to wait for a pong response before terminating the connection. */
const PONG_TIMEOUT_MS = 10_000

/**
 * How long a newly connected client has to send a `register` message.
 * Unregistered connections are closed after this window.
 */
const REGISTRATION_TIMEOUT_MS = 15_000

/**
 * TTL (in seconds) for Redis online-presence keys.
 * Refreshed on every heartbeat pong.  Allows ~2 missed pings before expiry.
 */
const PRESENCE_TTL_SECS = 90

/** Redis pub/sub channel for cross-instance relay routing. */
const RELAY_CHANNEL = 'encra:relay'

// ── Types ────────────────────────────────────────────────────────────────────

interface RelayMessage {
  type:          'register' | 'message'
  // Registration
  userId?:       string
  deviceId?:     string
  // Messaging
  to?:           string
  toDeviceId?:   string
  ciphertext?:   string
  nonce?:        string
  header?:       unknown   // Opaque ratchet header — forwarded as-is
  senderName?:   string
}

interface RedisRelayEnvelope {
  recipientKey: string
  payload:      string
}

// ── Module-level client map ───────────────────────────────────────────────────

/** Registered clients on THIS process instance.  Key: `${userId}:${deviceId}` */
const clients = new Map<string, WebSocket>()

// ── JWT auth ─────────────────────────────────────────────────────────────────

function authenticateWs(req: IncomingMessage): string | null {
  const url   = new URL(req.url ?? '', 'http://localhost')
  const token = url.searchParams.get('token')
  if (!token) return null

  const secret = process.env['JWT_SECRET']
  if (!secret) return null

  try {
    const payload = jwt.verify(token, secret) as { developerId: string }
    return payload.developerId ?? null
  } catch {
    return null
  }
}

// ── Database helpers ─────────────────────────────────────────────────────────

async function queueOfflineMessage(
  recipientId:       string,
  recipientDeviceId: string,
  senderId:          string,
  senderDeviceId:    string,
  ciphertext:        string,
  nonce:             string,
  header:            unknown,
  senderName:        string | undefined,
): Promise<void> {
  await getPool().query(
    `INSERT INTO message_queue
       (recipient_id, recipient_device_id, sender_id, sender_device_id, ciphertext, nonce, header, sender_name)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      recipientId,
      recipientDeviceId,
      senderId,
      senderDeviceId,
      ciphertext,
      nonce,
      JSON.stringify(header ?? {}),
      senderName ?? null,
    ],
  )
}

async function flushQueuedMessages(
  userId:   string,
  deviceId: string,
  socket:   WebSocket,
): Promise<void> {
  const result = await getPool().query<{
    id:                number
    sender_id:         string
    sender_device_id:  string
    ciphertext:        string
    nonce:             string
    header:            unknown
    sender_name:       string | null
  }>(
    `DELETE FROM message_queue
     WHERE recipient_id = $1 AND recipient_device_id = $2
     RETURNING id, sender_id, sender_device_id, ciphertext, nonce, header, sender_name`,
    [userId, deviceId],
  )

  for (const row of result.rows) {
    if (socket.readyState !== WebSocket.OPEN) break
    socket.send(JSON.stringify({
      type:         'message',
      from:         row.sender_id,
      fromDeviceId: row.sender_device_id,
      ciphertext:   row.ciphertext,
      nonce:        row.nonce,
      header:       row.header,
      ...(row.sender_name !== null && { senderName: row.sender_name }),
    }))
  }
}

// ── Redis pub/sub initialisation (runs once per process) ─────────────────────

let redisInitialised = false

function ensureRedisRelay(): void {
  if (redisInitialised) return
  redisInitialised = true

  const sub = getSubscriber()
  if (!sub) return   // No REDIS_URL — single-instance mode, nothing to do

  sub.subscribe(RELAY_CHANNEL).catch((err: Error) => {
    logger.warn({ err: err.message }, 'Redis subscribe failed — running in single-instance mode')
  })

  sub.on('message', (_channel: string, raw: string) => {
    try {
      const { recipientKey, payload } = JSON.parse(raw) as RedisRelayEnvelope
      const sock = clients.get(recipientKey)
      if (sock?.readyState === WebSocket.OPEN) {
        sock.send(payload)
      }
    } catch { /* ignore malformed pub/sub messages */ }
  })
}

// ── attachWebSocketRelay ─────────────────────────────────────────────────────

/**
 * Attaches a WebSocket relay to the HTTP server.
 *
 * Features:
 *  - JWT authentication on upgrade
 *  - Per-connection heartbeat (ping/pong every 30s, 10s pong timeout)
 *  - Registration timeout (client must register within 15s of connecting)
 *  - MAX_CONNECTIONS hard cap per instance
 *  - Redis pub/sub for cross-instance delivery (optional, falls back gracefully)
 *  - Online presence keys in Redis (SETEX, refreshed on heartbeat)
 *  - Offline message queuing in PostgreSQL for disconnected recipients
 */
export function attachWebSocketRelay(server: Server): WebSocketServer {
  ensureRedisRelay()

  const wss = new WebSocketServer({ server, path: '/v1/relay' })

  wss.on('connection', (socket: WebSocket, req: IncomingMessage) => {
    // ── Auth ──────────────────────────────────────────────────────────────────
    const developerId = authenticateWs(req)
    if (!developerId) {
      socket.close(4001, 'Unauthorized')
      return
    }

    // ── Connection cap ────────────────────────────────────────────────────────
    if (wss.clients.size > MAX_CONNECTIONS) {
      logger.warn({ total: wss.clients.size }, 'WebSocket connection limit reached')
      socket.close(1013, 'Server at capacity')
      return
    }

    logger.debug({ developerId, total: wss.clients.size }, 'WebSocket connected')

    // ── Per-connection state ──────────────────────────────────────────────────
    let registeredKey:      string | null = null
    let registeredUserId:   string | null = null
    let registeredDeviceId: string | null = null

    // ── Registration timeout ──────────────────────────────────────────────────
    const registrationTimer = setTimeout(() => {
      if (!registeredKey) {
        logger.warn({ developerId }, 'WebSocket registration timeout — closing')
        socket.close(4003, 'Registration timeout')
      }
    }, REGISTRATION_TIMEOUT_MS)

    // ── Heartbeat ─────────────────────────────────────────────────────────────
    let isAlive  = true
    let pongTimer: ReturnType<typeof setTimeout> | null = null

    socket.on('pong', () => {
      isAlive = true
      if (pongTimer) { clearTimeout(pongTimer); pongTimer = null }

      // Refresh Redis presence TTL on every successful heartbeat
      if (registeredKey) {
        const pub = getPublisher()
        if (pub) {
          pub.expire(`encra:online:${registeredKey}`, PRESENCE_TTL_SECS).catch(() => {})
        }
      }
    })

    const heartbeatInterval = setInterval(() => {
      if (!isAlive) {
        logger.warn({ key: registeredKey }, 'WebSocket heartbeat timeout — terminating')
        socket.terminate()
        return
      }
      isAlive  = false
      pongTimer = setTimeout(() => {
        if (!isAlive) {
          logger.warn({ key: registeredKey }, 'Pong not received in time — terminating')
          socket.terminate()
        }
      }, PONG_TIMEOUT_MS)
      socket.ping()
    }, HEARTBEAT_INTERVAL_MS)

    // ── Message handling ──────────────────────────────────────────────────────
    socket.on('message', (raw) => {
      if (Buffer.byteLength(raw as Buffer) > MAX_MESSAGE_BYTES) {
        socket.send(JSON.stringify({ type: 'error', message: 'Message too large (max 64 KB).' }))
        return
      }

      let msg: RelayMessage
      try {
        msg = JSON.parse(raw.toString()) as RelayMessage
      } catch {
        socket.send(JSON.stringify({ type: 'error', message: 'Invalid JSON.' }))
        return
      }

      // ── register ────────────────────────────────────────────────────────────
      if (msg.type === 'register') {
        if (!msg.userId || !msg.deviceId) {
          socket.send(JSON.stringify({ type: 'error', message: 'register requires userId and deviceId.' }))
          return
        }

        const newKey = `${msg.userId}:${msg.deviceId}`

        // If client re-registers under a different key, clean up the old entry
        if (registeredKey && registeredKey !== newKey) {
          clients.delete(registeredKey)
          clearPresence(registeredKey)
        }

        registeredUserId   = msg.userId
        registeredDeviceId = msg.deviceId
        registeredKey      = newKey
        clients.set(registeredKey, socket)
        clearTimeout(registrationTimer)

        // Advertise presence in Redis
        const pub = getPublisher()
        if (pub) {
          pub.setex(`encra:online:${registeredKey}`, PRESENCE_TTL_SECS, '1').catch(() => {})
        }

        flushQueuedMessages(msg.userId, msg.deviceId, socket).catch((err: Error) => {
          logger.warn({ err: err.message, key: registeredKey }, 'Failed to flush queued messages')
        })

        socket.send(JSON.stringify({ type: 'registered', userId: msg.userId, deviceId: msg.deviceId }))
        logger.debug({ key: registeredKey, developerId }, 'Client registered')
        return
      }

      // ── message ─────────────────────────────────────────────────────────────
      if (msg.type === 'message') {
        if (!registeredKey || !registeredUserId || !registeredDeviceId) {
          socket.send(JSON.stringify({ type: 'error', message: 'Must register before sending messages.' }))
          return
        }
        if (!msg.to || !msg.toDeviceId || !msg.ciphertext || !msg.nonce) {
          socket.send(JSON.stringify({
            type:    'error',
            message: 'message requires to, toDeviceId, ciphertext, and nonce.',
          }))
          return
        }

        const recipientKey = `${msg.to}:${msg.toDeviceId}`
        const payload      = JSON.stringify({
          type:         'message',
          from:         registeredUserId,
          fromDeviceId: registeredDeviceId,
          ciphertext:   msg.ciphertext,
          nonce:        msg.nonce,
          ...(msg.header     !== undefined && { header:     msg.header }),
          ...(msg.senderName !== undefined && { senderName: msg.senderName }),
        })

        deliverMessage(
          recipientKey,
          payload,
          msg.to,
          msg.toDeviceId,
          registeredUserId,
          registeredDeviceId,
          msg.ciphertext,
          msg.nonce,
          msg.header,
          msg.senderName,
          socket,
        ).catch((err: Error) => {
          logger.warn({ err: err.message, recipientKey }, 'Message delivery failed')
          socket.send(JSON.stringify({ type: 'error', message: 'Failed to deliver message.' }))
        })
        return
      }

      socket.send(JSON.stringify({ type: 'error', message: `Unknown message type: ${msg.type}` }))
    })

    // ── Clean up on close ─────────────────────────────────────────────────────
    socket.on('close', (code, reason) => {
      clearTimeout(registrationTimer)
      clearInterval(heartbeatInterval)
      if (pongTimer) clearTimeout(pongTimer)

      // Only remove from the map if this socket is still the registered one.
      // A rapid reconnect may have already replaced it.
      if (registeredKey && clients.get(registeredKey) === socket) {
        clients.delete(registeredKey)
        clearPresence(registeredKey)
      }

      logger.debug({ key: registeredKey, code, reason: reason.toString() }, 'WebSocket disconnected')
    })

    socket.on('error', (err) => {
      logger.warn({ err: err.message, key: registeredKey }, 'WebSocket socket error')
    })
  })

  logger.info({ path: '/v1/relay', maxConnections: MAX_CONNECTIONS }, 'WebSocket relay attached')
  return wss
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Remove online-presence key from Redis (best-effort). */
function clearPresence(key: string): void {
  const pub = getPublisher()
  if (pub) {
    pub.del(`encra:online:${key}`).catch(() => {})
  }
}

/**
 * Deliver a message to a recipient:
 *  1. Try local clients Map (same process)
 *  2. If not local and Redis is enabled, publish to Redis channel
 *     so another process instance can deliver it
 *  3. If recipient is confirmed offline (no presence key), queue in PostgreSQL
 */
async function deliverMessage(
  recipientKey:      string,
  payload:           string,
  recipientId:       string,
  recipientDeviceId: string,
  senderId:          string,
  senderDeviceId:    string,
  ciphertext:        string,
  nonce:             string,
  header:            unknown,
  senderName:        string | undefined,
  senderSocket:      WebSocket,
): Promise<void> {
  // ── Local delivery (same process) ─────────────────────────────────────────
  const recipientSocket = clients.get(recipientKey)
  if (recipientSocket?.readyState === WebSocket.OPEN) {
    recipientSocket.send(payload)
    return
  }

  const pub = getPublisher()
  if (pub) {
    // ── Cross-instance delivery via Redis pub/sub ──────────────────────────
    // Publish to the relay channel — any instance that has the recipient
    // connected will deliver it.
    await pub.publish(RELAY_CHANNEL, JSON.stringify({ recipientKey, payload }))

    // Check whether the recipient is online on *any* instance.
    // If so, the pub/sub delivery above will handle it.
    const isOnline = await pub.exists(`encra:online:${recipientKey}`)
    if (isOnline) return  // Another instance will deliver it

    // Recipient is offline on all instances — fall through to queue
  }

  // ── Offline queue ──────────────────────────────────────────────────────────
  await queueOfflineMessage(
    recipientId,
    recipientDeviceId,
    senderId,
    senderDeviceId,
    ciphertext,
    nonce,
    header,
    senderName,
  )

  void senderSocket  // suppress unused-var warning — caller uses it for error reporting
}
