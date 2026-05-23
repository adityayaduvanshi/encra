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
import {
  loadKeyPair,   saveKeyPair,
  loadRatchet,   saveRatchet,
  loadMessages,  saveMessages,
} from './ratchetStore.js'

export interface Message {
  from: string
  text: string
  timestamp: number
}

export interface WireEvent {
  direction: 'sent' | 'received'
  ciphertext: string
  nonce: string
  timestamp: number
}

export const ENCRA_SERVER_URL = 'https://api.encra.dev'

export interface UseE2EChatOptions {
  apiKey: string
  userId: string
  /** Defaults to the Encra managed server. */
  serverUrl?: string
  /** Called for recoverable per-message errors (e.g. DecryptionFailedError). */
  onError?: (err: Error) => void
  /** Called on every encrypted send/receive with the raw wire data. Useful for debugging. */
  onWireMessage?: (event: WireEvent) => void
}

export interface UseE2EChatResult {
  messages: Message[]
  /** True when the WebSocket is open and the user is registered. */
  isReady: boolean
  /** True during the initial connection or a reconnect attempt. */
  isConnecting: boolean
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

const BACKOFF_BASE_MS = 1000
const BACKOFF_MAX_MS  = 60_000
const MAX_MESSAGES    = 200

/**
 * React hook for sending and receiving end-to-end encrypted messages.
 *
 * Generates (or restores from IndexedDB) a key pair on mount, registers it
 * with the server, and connects a WebSocket relay. All Double Ratchet
 * encryption/decryption is handled internally. Ratchet state is persisted
 * to IndexedDB so conversations survive page reloads. The WebSocket reconnects
 * automatically with exponential backoff on unexpected disconnection.
 *
 * @param options.apiKey         - Developer API key (JWT).
 * @param options.userId         - Current user's identifier.
 * @param options.serverUrl      - Base URL of the Encra server.
 * @param options.onError        - Called for per-message recoverable errors.
 * @param options.onWireMessage  - Called on every send/receive with raw wire data.
 *
 * @example
 * const { sendMessage, messages, isReady, isConnecting } = useE2EChat({
 *   apiKey: 'e2e_live_xxx',
 *   userId: 'alice',
 * })
 */
export function useE2EChat({
  apiKey,
  userId,
  serverUrl = ENCRA_SERVER_URL,
  onError,
  onWireMessage,
}: UseE2EChatOptions): UseE2EChatResult {
  const [messages,    setMessages]    = useState<Message[]>([])
  const [isReady,     setIsReady]     = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [error,       setError]       = useState<Error | null>(null)

  const keyPairRef   = useRef<KeyPair | null>(null)
  const ratchetsRef  = useRef<Map<string, DoubleRatchet>>(new Map())
  const socketRef    = useRef<WebSocket | null>(null)

  // Stable refs so callbacks can change without restarting the effect
  const onErrorRef        = useRef(onError)
  const onWireMessageRef  = useRef(onWireMessage)
  useEffect(() => { onErrorRef.current = onError },       [onError])
  useEffect(() => { onWireMessageRef.current = onWireMessage }, [onWireMessage])

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
   * Returns the sender ratchet for `peerId`, restoring from IndexedDB if needed,
   * or creating a new one on first contact.
   */
  const getOrInitSenderRatchet = useCallback(
    async (peerId: string): Promise<DoubleRatchet> => {
      const key      = `s:${peerId}`
      const existing = ratchetsRef.current.get(key)
      if (existing) return existing

      const stored = await loadRatchet(userId, key)
      if (stored) {
        const ratchet = await DoubleRatchet.fromExport(stored)
        ratchetsRef.current.set(key, ratchet)
        return ratchet
      }

      const myKP    = keyPairRef.current
      if (!myKP) throw new Error('Key pair not initialised.')
      const peerPub = await fetchPeerPublicKey(peerId)
      const shared  = await deriveSharedSecret(myKP.privateKey, peerPub)
      const ratchet = await DoubleRatchet.initSender(shared, peerPub)
      ratchetsRef.current.set(key, ratchet)
      await saveRatchet(userId, key, ratchet.export())
      return ratchet
    },
    [userId, fetchPeerPublicKey]
  )

  /**
   * Returns the receiver ratchet for `peerId`, restoring from IndexedDB if needed,
   * or creating a new one on first contact.
   */
  const getOrInitReceiverRatchet = useCallback(
    async (peerId: string): Promise<DoubleRatchet> => {
      const key      = `r:${peerId}`
      const existing = ratchetsRef.current.get(key)
      if (existing) return existing

      const stored = await loadRatchet(userId, key)
      if (stored) {
        const ratchet = await DoubleRatchet.fromExport(stored)
        ratchetsRef.current.set(key, ratchet)
        return ratchet
      }

      const myKP    = keyPairRef.current
      if (!myKP) throw new Error('Key pair not initialised.')
      const peerPub = await fetchPeerPublicKey(peerId)
      const shared  = await deriveSharedSecret(myKP.privateKey, peerPub)
      const ratchet = await DoubleRatchet.initReceiver(shared, myKP)
      ratchetsRef.current.set(key, ratchet)
      await saveRatchet(userId, key, ratchet.export())
      return ratchet
    },
    [userId, fetchPeerPublicKey]
  )

  useEffect(() => {
    let cancelled    = false
    let retryCount   = 0
    let retryTimeout: ReturnType<typeof setTimeout> | null = null
    let ws: WebSocket | null = null

    function scheduleReconnect() {
      if (cancelled) return
      const base   = Math.min(BACKOFF_BASE_MS * Math.pow(2, retryCount++), BACKOFF_MAX_MS)
      const delay  = base * (0.75 + Math.random() * 0.5)
      setIsConnecting(true)
      retryTimeout = setTimeout(() => {
        if (!cancelled) connectWS()
      }, delay)
    }

    function connectWS() {
      ws = new WebSocket(`${wsBase}/v1/relay?token=${encodeURIComponent(apiKey)}`)
      socketRef.current = ws

      ws.addEventListener('open', () => {
        ws!.send(JSON.stringify({ type: 'register', userId }))
        retryCount = 0
        if (!cancelled) { setIsReady(true); setIsConnecting(false) }
      })

      ws.addEventListener('message', async (event) => {
        let msg: WireMessage
        try {
          msg = JSON.parse(event.data as string) as WireMessage
        } catch { return }

        if (msg.type !== 'message' || !msg.from || !msg.ciphertext || !msg.nonce || !msg.header) return

        onWireMessageRef.current?.({
          direction:  'received',
          ciphertext: msg.ciphertext,
          nonce:      msg.nonce,
          timestamp:  Date.now(),
        })

        try {
          const ratchet = await getOrInitReceiverRatchet(msg.from)
          const text = await ratchet.decrypt({
            header:     msg.header,
            ciphertext: importKey(msg.ciphertext),
            nonce:      importKey(msg.nonce),
          })
          await saveRatchet(userId, `r:${msg.from}`, ratchet.export())
          if (!cancelled) {
            setMessages((prev) => {
              const next   = [...prev, { from: msg.from!, text, timestamp: Date.now() }]
              const capped = next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next
              void saveMessages(userId, capped)
              return capped
            })
          }
        } catch (err) {
          if (err instanceof DecryptionFailedError) {
            const e = new DecryptionFailedError(`Decryption failed for message from '${msg.from}'.`)
            onErrorRef.current?.(e)
          }
        }
      })

      ws.addEventListener('error', () => {
        if (!cancelled) onErrorRef.current?.(new Error('WebSocket connection error.'))
      })

      ws.addEventListener('close', () => {
        if (!cancelled) {
          setIsReady(false)
          scheduleReconnect()
        }
      })
    }

    async function init() {
      try {
        setIsConnecting(true)
        await sodiumReady()

        // Restore or generate a stable key pair for this userId
        const stored = await loadKeyPair(userId)
        if (stored) {
          keyPairRef.current = {
            publicKey:  importKey(stored.pub),
            privateKey: importKey(stored.priv),
          }
        } else {
          const kp = await generateKeyPair()
          keyPairRef.current = kp
          await saveKeyPair(userId, { pub: exportKey(kp.publicKey), priv: exportKey(kp.privateKey) })
        }

        // Restore message history before opening the WebSocket
        const storedMsgs = await loadMessages(userId)
        if (!cancelled && storedMsgs.length > 0) setMessages(storedMsgs)

        if (cancelled) return

        // Register public key with the HTTP server (idempotent upsert)
        const regRes = await fetch(`${httpBase}/v1/keys`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ userId, publicKey: exportKey(keyPairRef.current.publicKey) }),
        })
        if (!regRes.ok) throw new Error(`Key registration failed: ${regRes.status}`)

        if (cancelled) return
        connectWS()
      } catch (err) {
        if (!cancelled) {
          setIsConnecting(false)
          setError(err instanceof Error ? err : new Error(String(err)))
        }
      }
    }

    void init()

    return () => {
      cancelled = true
      if (retryTimeout) clearTimeout(retryTimeout)
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
      await saveRatchet(userId, `s:${to}`, ratchet.export())

      const ctB64 = exportKey(ciphertext)
      const nB64  = exportKey(nonce)

      socket.send(JSON.stringify({ type: 'message', to, ciphertext: ctB64, nonce: nB64, header }))

      onWireMessageRef.current?.({
        direction:  'sent',
        ciphertext: ctB64,
        nonce:      nB64,
        timestamp:  Date.now(),
      })

      // Add sent message to local state and persist so it survives page reloads
      setMessages((prev) => {
        const next   = [...prev, { from: userId, text, timestamp: Date.now() }]
        const capped = next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next
        void saveMessages(userId, capped)
        return capped
      })
    },
    [userId, getOrInitSenderRatchet]
  )

  return { messages, isReady, isConnecting, sendMessage, error }
}
