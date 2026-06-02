import { useState, useEffect, useRef, useCallback } from 'react'
import {
  generateKeyPair,
  deriveSharedSecret,
  exportKey,
  importKey,
  sodiumReady,
  derivePresenceKey,
  encryptPresence,
  decryptPresence,
} from '@encra/core'
import type { KeyPair, PresencePayload, PresenceStatus } from '@encra/core'
import {
  loadKeyPair,   saveKeyPair,
  loadGhostMode, saveGhostMode,
  getOrCreateDeviceId,
} from './ratchetStore.js'

export type { PresenceStatus, PresencePayload }

interface DeviceKey {
  deviceId:  string
  publicKey: Uint8Array
}

/** Aggregated presence state for a single peer — last update wins. */
export interface PeerPresence {
  status:     PresenceStatus
  /** Unix epoch ms from the sender's device clock, or null if not yet received. */
  lastSeenAt: number | null
  isTyping:   boolean
}

export interface UseE2EPresenceOptions {
  apiKey:    string
  userId:    string
  /** User IDs whose presence you want to receive and broadcast your status to. */
  contacts:  string[]
  serverUrl?: string
  /** Called for recoverable per-message errors. */
  onError?:  (err: Error) => void
}

export interface UseE2EPresenceResult {
  /** Presence map keyed by userId — only populated after the first update arrives. */
  presence:     Record<string, PeerPresence>
  /** True when connected and registered with the relay. */
  isReady:      boolean
  /** True if ghost mode is active — your presence is hidden from others. */
  ghostMode:    boolean
  /**
   * Enable or disable ghost mode.
   * Enabling broadcasts `offline` to all contacts then suppresses future updates.
   * Disabling broadcasts `online` to all contacts.
   */
  setGhostMode: (enabled: boolean) => Promise<void>
  /**
   * Send a typing indicator to a specific contact.
   * Debounce this in your UI — calling on every keystroke floods the relay.
   */
  sendTyping:   (to: string, isTyping: boolean) => Promise<void>
  /** Broadcast your current status to every contact in `contacts`. */
  setStatus:    (status: PresenceStatus) => Promise<void>
  error:        Error | null
}

const ENCRA_SERVER_URL = 'https://api.encra.dev'
const PEER_KEY_TTL_MS  = 5 * 60 * 1_000
const BACKOFF_BASE_MS  = 1_000
const BACKOFF_MAX_MS   = 60_000

/**
 * React hook for encrypted presence: online/offline status, typing indicators,
 * last seen timestamps, and ghost mode.
 *
 * All presence fields travel as encrypted ciphertext — the server never sees
 * plaintext status, last-seen times, or typing state. Presence updates are
 * ephemeral: offline recipients do not receive queued updates.
 *
 * Encryption uses a symmetric key derived per device pair via:
 *   `BLAKE2b-256(ECDH(myPrivKey, theirPubKey), "encra:presence:v1")`
 *
 * @param options.apiKey    - Developer API key (JWT).
 * @param options.userId    - Current user's identifier.
 * @param options.contacts  - User IDs to track and broadcast presence to.
 * @param options.serverUrl - Base URL of the Encra server.
 * @param options.onError   - Called for recoverable errors.
 *
 * @example
 * const { presence, sendTyping, ghostMode, setGhostMode, setStatus } = useE2EPresence({
 *   apiKey:   'e2e_live_xxx',
 *   userId:   'alice',
 *   contacts: ['bob', 'carol'],
 * })
 * // Show typing indicator
 * await sendTyping('bob', true)
 * // Go invisible
 * await setGhostMode(true)
 */
export function useE2EPresence({
  apiKey,
  userId,
  contacts,
  serverUrl = ENCRA_SERVER_URL,
  onError,
}: UseE2EPresenceOptions): UseE2EPresenceResult {
  const [presence,   setPresence]   = useState<Record<string, PeerPresence>>({})
  const [isReady,    setIsReady]    = useState(false)
  const [ghostMode,  setGhostModeS] = useState(false)
  const [error,      setError]      = useState<Error | null>(null)

  const keyPairRef          = useRef<KeyPair | null>(null)
  const deviceIdRef         = useRef<string>('')
  const presenceKeysRef     = useRef<Map<string, Uint8Array>>(new Map())
  const peerKeyCacheRef     = useRef<Map<string, DeviceKey[]>>(new Map())
  const peerKeyCacheTimeRef = useRef<Map<string, number>>(new Map())
  const socketRef           = useRef<WebSocket | null>(null)
  const ghostModeRef        = useRef(false)
  const contactsRef         = useRef<string[]>(contacts)
  const didBroadcastOnlineRef = useRef(false)

  const onErrorRef = useRef(onError)
  useEffect(() => { onErrorRef.current = onError }, [onError])
  useEffect(() => { contactsRef.current = contacts }, [contacts])

  const httpBase = serverUrl.replace(/\/$/, '')
  const wsBase   = httpBase.replace(/^http/, 'ws')

  // ── Peer device key fetching ───────────────────────────────────────────────

  const fetchPeerDeviceKeys = useCallback(
    async (peerId: string): Promise<DeviceKey[]> => {
      const cached   = peerKeyCacheRef.current.get(peerId)
      const cachedAt = peerKeyCacheTimeRef.current.get(peerId) ?? 0
      if (cached && Date.now() - cachedAt < PEER_KEY_TTL_MS) return cached

      const res = await fetch(`${httpBase}/v1/keys/${peerId}`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      })
      if (!res.ok) throw new Error(`Could not fetch keys for '${peerId}': ${res.status}.`)

      const { devices } = (await res.json()) as {
        devices: Array<{ deviceId: string; publicKey: string }>
      }
      const keys: DeviceKey[] = devices.map((d) => ({
        deviceId:  d.deviceId,
        publicKey: importKey(d.publicKey),
      }))
      peerKeyCacheRef.current.set(peerId, keys)
      peerKeyCacheTimeRef.current.set(peerId, Date.now())
      return keys
    },
    [apiKey, httpBase],
  )

  // ── Presence key derivation ────────────────────────────────────────────────

  const getPresenceKeyFor = useCallback(
    async (peerId: string, device: DeviceKey): Promise<Uint8Array> => {
      const cacheKey = `${peerId}:${device.deviceId}`
      const cached   = presenceKeysRef.current.get(cacheKey)
      if (cached) return cached

      const myKP = keyPairRef.current
      if (!myKP) throw new Error('Key pair not initialised.')
      const shared = await deriveSharedSecret(myKP.privateKey, device.publicKey)
      const key    = await derivePresenceKey(shared)
      presenceKeysRef.current.set(cacheKey, key)
      return key
    },
    [],
  )

  // ── Presence send ──────────────────────────────────────────────────────────

  const sendPresenceTo = useCallback(
    async (to: string, payload: PresencePayload): Promise<void> => {
      const socket = socketRef.current
      if (!socket || socket.readyState !== WebSocket.OPEN) return
      if (ghostModeRef.current) return

      const devices = await fetchPeerDeviceKeys(to)
      for (const device of devices) {
        const presenceKey = await getPresenceKeyFor(to, device)
        const encrypted   = await encryptPresence(payload, presenceKey)
        socket.send(JSON.stringify({
          type:       'presence',
          to,
          toDeviceId: device.deviceId,
          ciphertext: encrypted.ciphertext,
          nonce:      encrypted.nonce,
        }))
      }
    },
    [fetchPeerDeviceKeys, getPresenceKeyFor],
  )

  // ── Main connection effect ─────────────────────────────────────────────────

  useEffect(() => {
    let cancelled    = false
    let retryCount   = 0
    let retryTimeout: ReturnType<typeof setTimeout> | null = null
    let ws: WebSocket | null = null

    function scheduleReconnect() {
      if (cancelled) return
      const base  = Math.min(BACKOFF_BASE_MS * Math.pow(2, retryCount++), BACKOFF_MAX_MS)
      const delay = base * (0.75 + Math.random() * 0.5)
      retryTimeout = setTimeout(() => { if (!cancelled) connectWS() }, delay)
    }

    function connectWS() {
      ws = new WebSocket(`${wsBase}/v1/relay?token=${encodeURIComponent(apiKey)}`)
      socketRef.current = ws

      ws.addEventListener('open', () => {
        ws!.send(JSON.stringify({ type: 'register', userId, deviceId: deviceIdRef.current }))
        retryCount = 0
        if (!cancelled) setIsReady(true)
      })

      ws.addEventListener('message', async (event) => {
        let msg: {
          type:          string
          from?:         string
          fromDeviceId?: string
          ciphertext?:   string
          nonce?:        string
        }
        try { msg = JSON.parse(event.data as string) } catch { return }

        if (
          msg.type !== 'presence' ||
          !msg.from || !msg.fromDeviceId || !msg.ciphertext || !msg.nonce
        ) return

        try {
          const devices      = await fetchPeerDeviceKeys(msg.from)
          const senderDevice = devices.find((d) => d.deviceId === msg.fromDeviceId)
          if (!senderDevice) return

          const presenceKey = await getPresenceKeyFor(msg.from, senderDevice)
          const payload     = await decryptPresence(
            { ciphertext: msg.ciphertext!, nonce: msg.nonce! },
            presenceKey,
          )

          if (!cancelled) {
            setPresence((prev) => ({
              ...prev,
              [msg.from!]: {
                status:     payload.status,
                lastSeenAt: payload.lastSeenAt,
                isTyping:   payload.isTyping,
              },
            }))
          }
        } catch (err) {
          onErrorRef.current?.(err instanceof Error ? err : new Error(String(err)))
        }
      })

      ws.addEventListener('error', () => {
        if (!cancelled) onErrorRef.current?.(new Error('Presence WebSocket error.'))
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
        await sodiumReady()

        const deviceId = await getOrCreateDeviceId(userId)
        deviceIdRef.current = deviceId

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

        const storedGhost = await loadGhostMode(userId)
        ghostModeRef.current = storedGhost
        if (!cancelled) setGhostModeS(storedGhost)

        // Register public key with the server (idempotent upsert)
        const regRes = await fetch(`${httpBase}/v1/keys`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
          body:    JSON.stringify({
            userId,
            publicKey: exportKey(keyPairRef.current.publicKey),
            deviceId,
          }),
        })
        if (!regRes.ok) throw new Error(`Key registration failed: ${regRes.status}`)

        if (!cancelled) connectWS()
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)))
      }
    }

    void init()

    return () => {
      cancelled = true

      // Best-effort: broadcast offline to contacts with cached presence keys.
      // Async encryption fires before socket.close() drains the send buffer.
      const socket = socketRef.current
      const myKP   = keyPairRef.current
      if (socket?.readyState === WebSocket.OPEN && myKP && !ghostModeRef.current) {
        const now = Date.now()
        for (const [contactId, devices] of peerKeyCacheRef.current) {
          for (const device of devices) {
            const pKey = presenceKeysRef.current.get(`${contactId}:${device.deviceId}`)
            if (!pKey) continue
            void encryptPresence({ status: 'offline', lastSeenAt: now, isTyping: false }, pKey)
              .then((enc) => {
                socket.send(JSON.stringify({
                  type:       'presence',
                  to:         contactId,
                  toDeviceId: device.deviceId,
                  ciphertext: enc.ciphertext,
                  nonce:      enc.nonce,
                }))
              })
              .catch(() => {})
          }
        }
      }

      if (retryTimeout) clearTimeout(retryTimeout)
      ws?.close()
      socketRef.current    = null
      keyPairRef.current   = null
      didBroadcastOnlineRef.current = false
      presenceKeysRef.current.clear()
      peerKeyCacheRef.current.clear()
      peerKeyCacheTimeRef.current.clear()
    }
  }, [apiKey, userId, httpBase, wsBase, fetchPeerDeviceKeys, getPresenceKeyFor])

  // ── Broadcast online once per connection ───────────────────────────────────

  useEffect(() => {
    if (!isReady) {
      didBroadcastOnlineRef.current = false
      return
    }
    if (didBroadcastOnlineRef.current || ghostModeRef.current) return
    didBroadcastOnlineRef.current = true

    const now = Date.now()
    for (const contactId of contactsRef.current) {
      void sendPresenceTo(contactId, { status: 'online', lastSeenAt: now, isTyping: false })
        .catch(() => {})
    }
  }, [isReady, sendPresenceTo])

  // ── Public API ─────────────────────────────────────────────────────────────

  const setGhostMode = useCallback(
    async (enabled: boolean): Promise<void> => {
      if (enabled === ghostModeRef.current) return

      if (enabled) {
        // Broadcast offline BEFORE enabling ghost mode so sendPresenceTo still fires
        for (const contactId of contactsRef.current) {
          await sendPresenceTo(contactId, {
            status:     'offline',
            lastSeenAt: Date.now(),
            isTyping:   false,
          }).catch(() => {})
        }
        ghostModeRef.current = true
      } else {
        ghostModeRef.current = false
        for (const contactId of contactsRef.current) {
          await sendPresenceTo(contactId, {
            status:     'online',
            lastSeenAt: Date.now(),
            isTyping:   false,
          }).catch(() => {})
        }
      }

      await saveGhostMode(userId, ghostModeRef.current)
      setGhostModeS(ghostModeRef.current)
    },
    [userId, sendPresenceTo],
  )

  const sendTyping = useCallback(
    async (to: string, isTyping: boolean): Promise<void> => {
      await sendPresenceTo(to, {
        status:     'online',
        lastSeenAt: Date.now(),
        isTyping,
      })
    },
    [sendPresenceTo],
  )

  const setStatus = useCallback(
    async (status: PresenceStatus): Promise<void> => {
      if (ghostModeRef.current) return
      const now = Date.now()
      for (const contactId of contactsRef.current) {
        await sendPresenceTo(contactId, { status, lastSeenAt: now, isTyping: false }).catch(() => {})
      }
    },
    [sendPresenceTo],
  )

  return { presence, isReady, ghostMode, setGhostMode, sendTyping, setStatus, error }
}
