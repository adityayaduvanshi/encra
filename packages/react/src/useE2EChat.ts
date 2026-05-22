import { useState, useEffect, useRef, useCallback } from 'react'
import {
  generateKeyPair,
  deriveSharedSecret,
  exportKey,
  importKey,
  sodiumReady,
  DecryptionFailedError,
  DoubleRatchet,
} from '@encra/core'
import type { KeyPair, MessageHeader } from '@encra/core'

export interface Message {
  from: string
  text: string
  timestamp: number
}

export const ENCRA_SERVER_URL = 'https://api.encra.dev'

export interface UseE2EChatOptions {
  apiKey: string
  userId: string
  serverUrl?: string  // defaults to Encra managed server
}

export interface UseE2EChatResult {
  messages: Message[]
  isReady: boolean
  sendMessage: (to: string, text: string) => Promise<void>
  error: Error | null
}

interface WireMessage {
  type: string
  from?: string
  ciphertext?: string
  nonce?: string
  header?: MessageHeader
}

/**
 * React hook for sending and receiving end-to-end encrypted messages.
 *
 * Generates a key pair on mount, registers it with the server, connects a
 * WebSocket relay, and handles all Double Ratchet encryption/decryption
 * internally. Every message uses a unique key — forward secrecy is automatic.
 *
 * @param options.apiKey    - Developer API key (JWT for server auth).
 * @param options.userId    - Current user's identifier.
 * @param options.serverUrl - Base URL of the e2e-chat-crypto server.
 * @returns `{ messages, isReady, sendMessage, error }`
 *
 * @example
 * const { sendMessage, messages, isReady } = useE2EChat({
 *   apiKey: 'e2e_live_xxx',
 *   userId: 'alice',
 *   serverUrl: 'https://api.example.com',
 * })
 */
export function useE2EChat({ apiKey, userId, serverUrl = ENCRA_SERVER_URL }: UseE2EChatOptions): UseE2EChatResult {
  const [messages, setMessages] = useState<Message[]>([])
  const [isReady, setIsReady] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  const keyPairRef  = useRef<KeyPair | null>(null)
  const ratchetsRef = useRef<Map<string, DoubleRatchet>>(new Map())
  const socketRef   = useRef<WebSocket | null>(null)

  const httpBase = serverUrl.replace(/\/$/, '')
  const wsBase   = httpBase.replace(/^http/, 'ws')

  const fetchPeerPublicKey = useCallback(
    async (peerId: string): Promise<Uint8Array> => {
      const res = await fetch(`${httpBase}/v1/keys/${peerId}`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      })
      if (!res.ok) {
        throw new Error(
          `Could not fetch public key for '${peerId}': ${res.status}. Make sure ${peerId} has registered.`
        )
      }
      const { publicKey: pubB64 } = (await res.json()) as { publicKey: string }
      return importKey(pubB64)
    },
    [apiKey, httpBase]
  )

  /**
   * Returns the existing sender ratchet for `peerId`, or initialises one.
   * Called when WE initiate a message to someone we haven't talked to before.
   * Keyed as `s:<peerId>` to avoid collision with the receiver ratchet.
   */
  const getOrInitSenderRatchet = useCallback(
    async (peerId: string): Promise<DoubleRatchet> => {
      const key      = `s:${peerId}`
      const existing = ratchetsRef.current.get(key)
      if (existing) return existing

      const myKP     = keyPairRef.current
      if (!myKP) throw new Error('Key pair not initialised.')

      const peerPub  = await fetchPeerPublicKey(peerId)
      const shared   = await deriveSharedSecret(myKP.privateKey, peerPub)
      const ratchet  = await DoubleRatchet.initSender(shared, peerPub)
      ratchetsRef.current.set(key, ratchet)
      return ratchet
    },
    [fetchPeerPublicKey]
  )

  /**
   * Returns the existing receiver ratchet for `peerId`, or initialises one.
   * Called when we receive the FIRST message from someone we haven't talked to.
   * Keyed as `r:<peerId>` to avoid collision with the sender ratchet.
   */
  const getOrInitReceiverRatchet = useCallback(
    async (peerId: string): Promise<DoubleRatchet> => {
      const key      = `r:${peerId}`
      const existing = ratchetsRef.current.get(key)
      if (existing) return existing

      const myKP     = keyPairRef.current
      if (!myKP) throw new Error('Key pair not initialised.')

      const peerPub  = await fetchPeerPublicKey(peerId)
      const shared   = await deriveSharedSecret(myKP.privateKey, peerPub)
      const ratchet  = await DoubleRatchet.initReceiver(shared, myKP)
      ratchetsRef.current.set(key, ratchet)
      return ratchet
    },
    [fetchPeerPublicKey]
  )

  useEffect(() => {
    let cancelled = false
    let ws: WebSocket | null = null

    async function init() {
      try {
        await sodiumReady()

        const keyPair = await generateKeyPair()
        keyPairRef.current = keyPair

        // Register public key with server
        const regRes = await fetch(`${httpBase}/v1/keys`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ userId, publicKey: exportKey(keyPair.publicKey) }),
        })
        if (!regRes.ok) throw new Error(`Key registration failed: ${regRes.status}`)

        if (cancelled) return

        ws = new WebSocket(`${wsBase}/v1/relay?token=${encodeURIComponent(apiKey)}`)
        socketRef.current = ws

        ws.addEventListener('open', () => {
          ws!.send(JSON.stringify({ type: 'register', userId }))
          if (!cancelled) setIsReady(true)
        })

        ws.addEventListener('message', async (event) => {
          let msg: WireMessage
          try {
            msg = JSON.parse(event.data as string) as WireMessage
          } catch {
            return
          }

          if (msg.type !== 'message' || !msg.from || !msg.ciphertext || !msg.nonce || !msg.header) return

          try {
            const ratchet = await getOrInitReceiverRatchet(msg.from)
            const text = await ratchet.decrypt({
              header:     msg.header,
              ciphertext: importKey(msg.ciphertext),
              nonce:      importKey(msg.nonce),
            })
            if (!cancelled) {
              setMessages((prev) => [...prev, { from: msg.from!, text, timestamp: Date.now() }])
            }
          } catch (err) {
            if (err instanceof DecryptionFailedError) {
              console.error('[e2e-chat] Decryption failed for message from', msg.from)
            }
          }
        })

        ws.addEventListener('error', () => {
          if (!cancelled) setError(new Error('WebSocket connection error.'))
        })

        ws.addEventListener('close', () => {
          if (!cancelled) setIsReady(false)
        })
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)))
      }
    }

    void init()

    return () => {
      cancelled = true
      ws?.close()
      socketRef.current = null
      keyPairRef.current = null
      ratchetsRef.current.clear()
    }
  }, [apiKey, userId, httpBase, wsBase, getOrInitReceiverRatchet])

  const sendMessage = useCallback(
    async (to: string, text: string): Promise<void> => {
      const socket = socketRef.current
      if (!socket || socket.readyState !== WebSocket.OPEN) {
        throw new Error('WebSocket is not connected. Wait for isReady to be true.')
      }

      const ratchet = await getOrInitSenderRatchet(to)
      const { header, ciphertext, nonce } = await ratchet.encrypt(text)

      socket.send(
        JSON.stringify({
          type: 'message',
          to,
          ciphertext: exportKey(ciphertext),
          nonce:      exportKey(nonce),
          header,
        })
      )
    },
    [getOrInitSenderRatchet]
  )

  return { messages, isReady, sendMessage, error }
}
