import { useState, useEffect, useRef, useCallback } from 'react'
import {
  generateKeyPair,
  exportKey,
  importKey,
  sodiumReady,
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  x3dhInitiate,
  x3dhRespond,
  derivePresenceKey,
  encryptPresence,
  decryptPresence,
  DecryptionFailedError,
} from '@encra/core'
import type {
  KeyPair,
  IdentityKeyPair,
  PreKeyBundle,
  PreKeyMessage,
  PresencePayload,
  PresenceStatus,
} from '@encra/core'
import {
  loadKeyPair,          saveKeyPair,
  loadPreKeys,          savePreKeys,
  loadGhostMode,        saveGhostMode,
  loadPresenceSession,  savePresenceSession,
  getOrCreateDeviceId,
  type StoredPreKeys,
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
const OTP_POOL_SIZE    = 100

/**
 * React hook for encrypted presence: online/offline status, typing indicators,
 * last-seen timestamps, and ghost mode.
 *
 * All presence fields travel as encrypted ciphertext — the server never sees
 * plaintext status, last-seen times, or typing state. Presence updates are
 * ephemeral: offline recipients do not receive queued updates.
 *
 * **Encryption (Signal-grade, session-derived).** Each direction of a contact
 * relationship gets its own authenticated X3DH session (3-DH variant — the
 * signed-prekey signature is verified, so a key-substituting server is
 * defeated). The presence key is `derivePresenceKey(sessionRootKey)`, so it is
 * cryptographically isolated from chat message keys and rotates whenever the
 * session is re-established (forward secrecy at session granularity). Presence
 * sessions never consume one-time prekeys, so they don't drain the chat pool.
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
 * await sendTyping('bob', true) // show typing indicator
 * await setGhostMode(true)      // go invisible
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
  const identityRef         = useRef<IdentityKeyPair | null>(null)
  const prekeysRef          = useRef<StoredPreKeys | null>(null)
  const deviceIdRef         = useRef<string>('')
  /** Outbound (initiator) presence keys, keyed `${peerId}:${deviceId}`. */
  const sendKeysRef         = useRef<Map<string, Uint8Array>>(new Map())
  /** Inbound (responder) presence keys, keyed `${peerId}:${deviceId}`. */
  const recvKeysRef         = useRef<Map<string, Uint8Array>>(new Map())
  /** X3DH prekey message to attach to outbound frames, keyed `${peerId}:${deviceId}`. */
  const sendPrekeyRef       = useRef<Map<string, PreKeyMessage>>(new Map())
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

  // ── Peer device key fetching (for routing) ──────────────────────────────────

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

  // ── Prekey material (shared with useE2EChat via the same IndexedDB store) ────

  const publishPreKeys = useCallback(async (): Promise<void> => {
    const pk = prekeysRef.current
    if (!pk || !deviceIdRef.current) return
    try {
      const res = await fetch(`${httpBase}/v1/prekeys`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body:    JSON.stringify({
          userId,
          deviceId:     deviceIdRef.current,
          identityKey:  pk.identityPub,
          signedPreKey: {
            keyId:     pk.signedPreKey.keyId,
            publicKey: pk.signedPreKey.pub,
            signature: pk.signedPreKey.signature,
          },
          oneTimePreKeys: pk.oneTimePreKeys.map((o) => ({ keyId: o.keyId, publicKey: o.pub })),
        }),
      })
      if (!res.ok) onErrorRef.current?.(new Error(`Prekey publish failed: ${res.status}`))
    } catch (err) {
      onErrorRef.current?.(err instanceof Error ? err : new Error('Prekey publish failed.'))
    }
  }, [apiKey, httpBase, userId])

  /** Restore or generate this device's identity + signed prekey + OTP pool. */
  const ensurePreKeys = useCallback(async (): Promise<void> => {
    const stored = await loadPreKeys(userId)
    if (stored) {
      prekeysRef.current  = stored
      identityRef.current = {
        publicKey:  importKey(stored.identityPub),
        privateKey: importKey(stored.identityPriv),
      }
      return
    }

    const identity = await generateIdentityKeyPair()
    const spk      = await generateSignedPreKey(identity, 1)
    const otps     = await generateOneTimePreKeys(1, OTP_POOL_SIZE)

    identityRef.current = identity
    prekeysRef.current  = {
      identityPub:  exportKey(identity.publicKey),
      identityPriv: exportKey(identity.privateKey),
      signedPreKey: {
        keyId:     spk.keyId,
        pub:       exportKey(spk.keyPair.publicKey),
        priv:      exportKey(spk.keyPair.privateKey),
        signature: exportKey(spk.signature),
      },
      oneTimePreKeys: otps.map((o) => ({
        keyId: o.keyId,
        pub:   exportKey(o.keyPair.publicKey),
        priv:  exportKey(o.keyPair.privateKey),
      })),
      nextOtpId: OTP_POOL_SIZE + 1,
    }
    await savePreKeys(userId, prekeysRef.current)
    await publishPreKeys()
  }, [userId, publishPreKeys])

  /** Fetch a peer device's prekey bundle WITHOUT consuming a one-time prekey. */
  const fetchPresenceBundle = useCallback(
    async (peerId: string, deviceId: string): Promise<PreKeyBundle> => {
      const res = await fetch(
        `${httpBase}/v1/prekeys/${encodeURIComponent(peerId)}/${encodeURIComponent(deviceId)}?consumeOneTime=false`,
        { headers: { Authorization: `Bearer ${apiKey}` } },
      )
      if (!res.ok) {
        throw new Error(
          `Could not fetch presence bundle for '${peerId}' device '${deviceId}': ${res.status}.`,
        )
      }
      return (await res.json()) as PreKeyBundle
    },
    [apiKey, httpBase],
  )

  // ── Presence session establishment ──────────────────────────────────────────

  /** Outbound presence key for a peer device (we are the X3DH initiator). */
  const getSendPresenceKey = useCallback(
    async (peerId: string, deviceId: string): Promise<Uint8Array> => {
      const cacheKey = `${peerId}:${deviceId}`
      const cached   = sendKeysRef.current.get(cacheKey)
      if (cached) return cached

      const stored = await loadPresenceSession(userId, `ps:${cacheKey}`)
      if (stored) {
        const key = importKey(stored.key)
        sendKeysRef.current.set(cacheKey, key)
        if (stored.prekey) sendPrekeyRef.current.set(cacheKey, stored.prekey)
        return key
      }

      const myIdentity = identityRef.current
      if (!myIdentity) throw new Error('Identity key not initialised.')

      // 3-DH X3DH (no one-time prekey): signature verified inside x3dhInitiate.
      const bundle = await fetchPresenceBundle(peerId, deviceId)
      const init   = await x3dhInitiate(myIdentity, bundle)
      const key    = await derivePresenceKey(init.sessionKeys.rootKey)

      sendKeysRef.current.set(cacheKey, key)
      sendPrekeyRef.current.set(cacheKey, init.message)
      await savePresenceSession(userId, `ps:${cacheKey}`, {
        key:    exportKey(key),
        prekey: init.message,
      })
      return key
    },
    [userId, fetchPresenceBundle],
  )

  /** Inbound presence key for a peer device (we respond to their X3DH prekey). */
  const establishRecvPresenceKey = useCallback(
    async (peerId: string, fromDeviceId: string, prekey: PreKeyMessage): Promise<Uint8Array> => {
      const myIdentity = identityRef.current
      const pk         = prekeysRef.current
      if (!myIdentity || !pk) throw new Error('Prekeys not initialised.')

      if (prekey.signedPreKeyId !== pk.signedPreKey.keyId) {
        throw new DecryptionFailedError(
          `Signed prekey ${prekey.signedPreKeyId} is no longer available (current is ${pk.signedPreKey.keyId}).`,
        )
      }
      const signedPair: KeyPair = {
        publicKey:  importKey(pk.signedPreKey.pub),
        privateKey: importKey(pk.signedPreKey.priv),
      }
      // Presence X3DH never uses a one-time prekey (3-DH variant).
      const keys = await x3dhRespond(myIdentity, signedPair, null, prekey)
      const key  = await derivePresenceKey(keys.rootKey)

      const cacheKey = `${peerId}:${fromDeviceId}`
      recvKeysRef.current.set(cacheKey, key)
      await savePresenceSession(userId, `pr:${cacheKey}`, { key: exportKey(key) })
      return key
    },
    [userId],
  )

  /** Get a cached/persisted inbound presence key without establishing. */
  const loadRecvPresenceKey = useCallback(
    async (peerId: string, fromDeviceId: string): Promise<Uint8Array | null> => {
      const cacheKey = `${peerId}:${fromDeviceId}`
      const cached   = recvKeysRef.current.get(cacheKey)
      if (cached) return cached
      const stored = await loadPresenceSession(userId, `pr:${cacheKey}`)
      if (stored) {
        const key = importKey(stored.key)
        recvKeysRef.current.set(cacheKey, key)
        return key
      }
      return null
    },
    [userId],
  )

  // ── Presence send ────────────────────────────────────────────────────────────

  const sendPresenceTo = useCallback(
    async (to: string, payload: PresencePayload): Promise<void> => {
      const socket = socketRef.current
      if (!socket || socket.readyState !== WebSocket.OPEN) return
      if (ghostModeRef.current) return

      const devices = await fetchPeerDeviceKeys(to)
      for (const device of devices) {
        const presenceKey = await getSendPresenceKey(to, device.deviceId)
        const encrypted   = await encryptPresence(payload, presenceKey)
        const prekey      = sendPrekeyRef.current.get(`${to}:${device.deviceId}`)
        socket.send(JSON.stringify({
          type:       'presence',
          to,
          toDeviceId: device.deviceId,
          ciphertext: encrypted.ciphertext,
          nonce:      encrypted.nonce,
          // Attach the prekey so the recipient can establish the same session.
          ...(prekey && { prekey }),
        }))
      }
    },
    [fetchPeerDeviceKeys, getSendPresenceKey],
  )

  // ── Main connection effect ───────────────────────────────────────────────────

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
      ws = new WebSocket(`${wsBase}/v1/relay`)
      socketRef.current = ws

      ws.addEventListener('open', () => {
        ws!.send(JSON.stringify({ type: 'auth', token: apiKey }))
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
          prekey?:       PreKeyMessage
        }
        try { msg = JSON.parse(event.data as string) } catch { return }

        if (
          msg.type !== 'presence' ||
          !msg.from || !msg.fromDeviceId || !msg.ciphertext || !msg.nonce
        ) return

        const enc = { ciphertext: msg.ciphertext, nonce: msg.nonce }

        try {
          // Try an existing inbound session first.
          let key = await loadRecvPresenceKey(msg.from, msg.fromDeviceId)
          let payload: PresencePayload | null = null

          if (key) {
            try {
              payload = await decryptPresence(enc, key)
            } catch (err) {
              if (!(err instanceof DecryptionFailedError) || !msg.prekey) throw err
              // Stale session and the frame carries a fresh prekey — re-establish.
              key = null
            }
          }

          if (!payload) {
            if (!msg.prekey) {
              throw new DecryptionFailedError(
                `No presence session with '${msg.from}' and no prekey to establish one.`,
              )
            }
            const fresh = await establishRecvPresenceKey(msg.from, msg.fromDeviceId, msg.prekey)
            payload = await decryptPresence(enc, fresh)
          }

          if (!cancelled && payload) {
            const p = payload
            setPresence((prev) => ({
              ...prev,
              [msg.from!]: { status: p.status, lastSeenAt: p.lastSeenAt, isTyping: p.isTyping },
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

        // Register device public key (idempotent upsert) so we appear in /v1/keys.
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

        if (cancelled) return
        await ensurePreKeys()

        if (!cancelled) connectWS()
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)))
      }
    }

    void init()

    return () => {
      cancelled = true

      // Best-effort offline broadcast to contacts with an established send key.
      const socket = socketRef.current
      if (socket?.readyState === WebSocket.OPEN && !ghostModeRef.current) {
        const now = Date.now()
        for (const [cacheKey, pKey] of sendKeysRef.current) {
          const sep = cacheKey.lastIndexOf(':')
          const to  = cacheKey.slice(0, sep)
          const dev = cacheKey.slice(sep + 1)
          const prekey = sendPrekeyRef.current.get(cacheKey)
          void encryptPresence({ status: 'offline', lastSeenAt: now, isTyping: false }, pKey)
            .then((enc) => {
              socket.send(JSON.stringify({
                type: 'presence', to, toDeviceId: dev,
                ciphertext: enc.ciphertext, nonce: enc.nonce,
                ...(prekey && { prekey }),
              }))
            })
            .catch(() => {})
        }
      }

      if (retryTimeout) clearTimeout(retryTimeout)
      ws?.close()
      socketRef.current  = null
      keyPairRef.current = null
      identityRef.current = null
      prekeysRef.current  = null
      didBroadcastOnlineRef.current = false
      sendKeysRef.current.clear()
      recvKeysRef.current.clear()
      sendPrekeyRef.current.clear()
      peerKeyCacheRef.current.clear()
      peerKeyCacheTimeRef.current.clear()
    }
  }, [apiKey, userId, httpBase, wsBase, ensurePreKeys, getSendPresenceKey, establishRecvPresenceKey, loadRecvPresenceKey])

  // ── Broadcast online once per connection ──────────────────────────────────────

  useEffect(() => {
    if (!isReady) {
      didBroadcastOnlineRef.current = false
      return
    }
    if (didBroadcastOnlineRef.current || ghostModeRef.current) return
    didBroadcastOnlineRef.current = true

    const now = Date.now()
    for (const contactId of contactsRef.current) {
      void sendPresenceTo(contactId, { status: 'online', lastSeenAt: now, isTyping: false }).catch(() => {})
    }
  }, [isReady, sendPresenceTo])

  // ── Public API ─────────────────────────────────────────────────────────────

  const setGhostMode = useCallback(
    async (enabled: boolean): Promise<void> => {
      if (enabled === ghostModeRef.current) return

      if (enabled) {
        // Broadcast offline BEFORE enabling so sendPresenceTo still fires.
        for (const contactId of contactsRef.current) {
          await sendPresenceTo(contactId, { status: 'offline', lastSeenAt: Date.now(), isTyping: false })
            .catch(() => {})
        }
        ghostModeRef.current = true
      } else {
        ghostModeRef.current = false
        for (const contactId of contactsRef.current) {
          await sendPresenceTo(contactId, { status: 'online', lastSeenAt: Date.now(), isTyping: false })
            .catch(() => {})
        }
      }

      await saveGhostMode(userId, ghostModeRef.current)
      setGhostModeS(ghostModeRef.current)
    },
    [userId, sendPresenceTo],
  )

  const sendTyping = useCallback(
    async (to: string, isTyping: boolean): Promise<void> => {
      await sendPresenceTo(to, { status: 'online', lastSeenAt: Date.now(), isTyping })
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
