import { WebSocketServer, WebSocket } from 'ws'
import { IncomingMessage, Server } from 'http'
import jwt from 'jsonwebtoken'
import { getPool } from '../db/pool.js'

interface RelayMessage {
  type: 'register' | 'message'
  userId?: string
  to?: string
  from?: string
  ciphertext?: string
  nonce?: string
  header?: unknown     // Opaque ratchet header — forwarded as-is to recipient
  senderName?: string  // Display name set by the sender client — forwarded as-is
}

const clients = new Map<string, WebSocket>()

/** Maximum allowed size for a single WebSocket message (64 KB). */
const MAX_MESSAGE_BYTES = 64 * 1024

function authenticateWs(req: IncomingMessage): string | null {
  const url = new URL(req.url ?? '', 'http://localhost')
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
  recipientId: string,
  senderId: string,
  ciphertext: string,
  nonce: string,
  header: unknown,
  senderName: string | undefined,
): Promise<void> {
  const pool = getPool()
  await pool.query(
    `INSERT INTO message_queue (recipient_id, sender_id, ciphertext, nonce, header, sender_name)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [recipientId, senderId, ciphertext, nonce, JSON.stringify(header ?? {}), senderName ?? null]
  )
}

async function flushQueuedMessages(userId: string, socket: WebSocket): Promise<void> {
  const pool = getPool()
  const result = await pool.query<{
    id: number
    sender_id: string
    ciphertext: string
    nonce: string
    header: unknown
    sender_name: string | null
  }>(
    `DELETE FROM message_queue WHERE recipient_id = $1
     RETURNING id, sender_id, ciphertext, nonce, header, sender_name`,
    [userId]
  )
  for (const row of result.rows) {
    socket.send(JSON.stringify({
      type:       'message',
      from:       row.sender_id,
      ciphertext: row.ciphertext,
      nonce:      row.nonce,
      header:     row.header,
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

    let registeredUserId: string | null = null

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

      if (msg.type === 'register') {
        if (!msg.userId) {
          socket.send(JSON.stringify({ type: 'error', message: 'register requires userId.' }))
          return
        }
        registeredUserId = msg.userId
        clients.set(registeredUserId, socket)
        flushQueuedMessages(registeredUserId, socket).catch(() => {
          // Non-fatal — messages remain in queue for next connection
        })
        socket.send(JSON.stringify({ type: 'registered', userId: registeredUserId }))
        return
      }

      if (msg.type === 'message') {
        if (!registeredUserId) {
          socket.send(JSON.stringify({ type: 'error', message: 'Must register before sending messages.' }))
          return
        }
        if (!msg.to || !msg.ciphertext || !msg.nonce) {
          socket.send(JSON.stringify({ type: 'error', message: 'message requires to, ciphertext, and nonce.' }))
          return
        }

        const recipientSocket = clients.get(msg.to)
        const payload = JSON.stringify({
          type: 'message',
          from: registeredUserId,
          ciphertext: msg.ciphertext,
          nonce: msg.nonce,
          ...(msg.header      !== undefined && { header:     msg.header }),
          ...(msg.senderName  !== undefined && { senderName: msg.senderName }),
        })

        if (recipientSocket && recipientSocket.readyState === WebSocket.OPEN) {
          recipientSocket.send(payload)
        } else {
          queueOfflineMessage(msg.to, registeredUserId, msg.ciphertext, msg.nonce, msg.header, msg.senderName).catch(() => {
            socket.send(JSON.stringify({ type: 'error', message: 'Failed to queue message for offline recipient.' }))
          })
        }
        return
      }

      socket.send(JSON.stringify({ type: 'error', message: `Unknown message type: ${msg.type}` }))
    })

    socket.on('close', () => {
      if (registeredUserId) clients.delete(registeredUserId)
    })
  })

  return wss
}
