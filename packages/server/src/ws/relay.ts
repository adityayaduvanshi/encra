import { WebSocketServer, WebSocket } from 'ws'
import { IncomingMessage, Server } from 'http'
import jwt from 'jsonwebtoken'
import { getPool } from '../db/pool.js'

interface RelayMessage {
  type:          'register' | 'message'
  // Registration
  userId?:       string
  deviceId?:     string   // sender's device ID
  // Messaging
  to?:           string
  toDeviceId?:   string   // recipient's device ID
  ciphertext?:   string
  nonce?:        string
  header?:       unknown  // Opaque ratchet header — forwarded as-is
  senderName?:   string
}

/** clients key: `${userId}:${deviceId}` */
const clients = new Map<string, WebSocket>()

/** Maximum allowed size for a single WebSocket message (64 KB). */
const MAX_MESSAGE_BYTES = 64 * 1024

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
  const pool = getPool()
  await pool.query(
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
    ]
  )
}

async function flushQueuedMessages(
  userId:   string,
  deviceId: string,
  socket:   WebSocket,
): Promise<void> {
  const pool   = getPool()
  const result = await pool.query<{
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
    [userId, deviceId]
  )
  for (const row of result.rows) {
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

export function attachWebSocketRelay(server: Server): WebSocketServer {
  const wss = new WebSocketServer({ server, path: '/v1/relay' })

  wss.on('connection', (socket: WebSocket, req: IncomingMessage) => {
    const developerId = authenticateWs(req)
    if (!developerId) {
      socket.close(4001, 'Unauthorized')
      return
    }

    let registeredKey:      string | null = null  // `${userId}:${deviceId}`
    let registeredUserId:   string | null = null
    let registeredDeviceId: string | null = null

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
        // Remove previous entry if the client re-registers under a different key
        // (prevents stale entries accumulating in the clients map)
        if (registeredKey && registeredKey !== newKey) clients.delete(registeredKey)
        registeredUserId   = msg.userId
        registeredDeviceId = msg.deviceId
        registeredKey      = newKey
        clients.set(registeredKey, socket)

        flushQueuedMessages(msg.userId, msg.deviceId, socket).catch(() => {
          // Non-fatal — messages remain in queue for next connection
        })

        socket.send(JSON.stringify({ type: 'registered', userId: msg.userId, deviceId: msg.deviceId }))
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
            type: 'error',
            message: 'message requires to, toDeviceId, ciphertext, and nonce.',
          }))
          return
        }

        const recipientKey    = `${msg.to}:${msg.toDeviceId}`
        const recipientSocket = clients.get(recipientKey)
        const payload         = JSON.stringify({
          type:         'message',
          from:         registeredUserId,
          fromDeviceId: registeredDeviceId,
          ciphertext:   msg.ciphertext,
          nonce:        msg.nonce,
          ...(msg.header     !== undefined && { header:     msg.header }),
          ...(msg.senderName !== undefined && { senderName: msg.senderName }),
        })

        if (recipientSocket && recipientSocket.readyState === WebSocket.OPEN) {
          recipientSocket.send(payload)
        } else {
          queueOfflineMessage(
            msg.to,
            msg.toDeviceId,
            registeredUserId,
            registeredDeviceId,
            msg.ciphertext,
            msg.nonce,
            msg.header,
            msg.senderName,
          ).catch(() => {
            socket.send(JSON.stringify({ type: 'error', message: 'Failed to queue message for offline recipient.' }))
          })
        }
        return
      }

      socket.send(JSON.stringify({ type: 'error', message: `Unknown message type: ${msg.type}` }))
    })

    socket.on('close', () => {
      // Only remove this socket if it's still the one registered under the key.
      // A rapid reconnect may have already replaced it in the map.
      if (registeredKey && clients.get(registeredKey) === socket) clients.delete(registeredKey)
    })
  })

  return wss
}
