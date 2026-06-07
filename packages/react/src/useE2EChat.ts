import { useState, useEffect, useRef, useCallback } from 'react'
import {
  generateKeyPair,
  exportKey,
  importKey,
  sodiumReady,
  DecryptionFailedError,
  DoubleRatchet,
  generateOneTimePreKeys,
  x3dhInitiate,
  x3dhRespond,
} from '@encra/core'
import type { KeyPair, IdentityKeyPair, PreKeyBundle, PreKeyMessage } from '@encra/core'
import {
  loadKeyPair,   saveKeyPair,
  loadRatchet,   saveRatchet,
  loadMessages,  saveMessages,
  savePreKeys,   loadOrCreatePreKeys,
  getOrCreateDeviceId,
  type StoredPreKeys,
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

/**
 * A single device entry returned by the key server for a given user.
 * Encra assigns each browser/device a stable UUID; each device registers
 * its own X25519 public key so that messages can be routed and decrypted
 * independently on every device the user is logged in to.
 */
export interface DeviceKey {
  /** The stable device UUID generated on first use and persisted in IndexedDB. */
  deviceId:  string
  /** The X25519 public key registered by this device. */
  publicKey: Uint8Array
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

/**
 * A message on the wire. `encHeader` is the ratchet header encrypted under the
 * sending header key (the relay never sees ratchet metadata). `prekey` carries
 * the X3DH prekey message on a session's first inbound message(s); it travels
 * alongside the encrypted header because it must be readable before any header
 * key exists.
 */
interface WireMessage {
  type: string
  from?: string
  /** Sender's device UUID — used to key the per-device receiver ratchet. */
  fromDeviceId?: string
  ciphertext?: string
  nonce?: string
  encHeader?: string
  prekey?: PreKeyMessage
}

const BACKOFF_BASE_MS  = 1000
const BACKOFF_MAX_MS   = 60_000
const MAX_MESSAGES     = 200
/** Re-fetch peer device list after this many ms — ensures new devices are seen. */
const PEER_KEY_TTL_MS  = 5 * 60 * 1_000
/** Number of one-time prekeys to publish when first registering. */
const OTP_POOL_SIZE    = 100
/** Replenish the one-time prekey pool when it drops to this many or fewer. */
const OTP_LOW_WATER    = 20

/**
 * React hook for sending and receiving end-to-end encrypted messages.
 *
 * Generates (or restores from IndexedDB) a device-stable key pair on mount,
 * registers it with the server alongside a unique device ID, and connects a
 * WebSocket relay. All Double Ratchet encryption/decryption is handled
 * internally. Ratchet state is persisted to IndexedDB so conversations survive
 * page reloads. The WebSocket reconnects automatically with exponential backoff
 * on unexpected disconnection.
 *
 * Multi-device: if the recipient has several registered devices, `sendMessage`
 * encrypts and delivers one message per device so the conversation appears on
 * all of the recipient's devices simultaneously.
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
  const [messages,     setMessages]     = useState<Message[]>([])
  const [isReady,      setIsReady]      = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [error,        setError]        = useState<Error | null>(null)

  const keyPairRef          = useRef<KeyPair | null>(null)
  const identityRef         = useRef<IdentityKeyPair | null>(null)
  const prekeysRef          = useRef<StoredPreKeys | null>(null)
  const deviceIdRef         = useRef<string>('')
  const ratchetsRef         = useRef<Map<string, DoubleRatchet>>(new Map())
  /** Pending X3DH prekey messages, keyed `${peerId}:${deviceId}` (sender side). */
  const pendingPrekeyRef    = useRef<Map<string, PreKeyMessage>>(new Map())
  const peerKeyCacheRef     = useRef<Map<string, DeviceKey[]>>(new Map())
  const peerKeyCacheTimeRef = useRef<Map<string, number>>(new Map())
  const socketRef           = useRef<WebSocket | null>(null)

  // Stable refs so callbacks can change without restarting the effect
  const onErrorRef       = useRef(onError)
  const onWireMessageRef = useRef(onWireMessage)
  useEffect(() => { onErrorRef.current = onError },            [onError])
  useEffect(() => { onWireMessageRef.current = onWireMessage }, [onWireMessage])

  const httpBase = serverUrl.replace(/\/$/, '')
  const wsBase   = httpBase.replace(/^http/, 'ws')

  /**
   * Fetches all registered device keys for `peerId` and caches them in memory.
   * Returns an array of `DeviceKey` (one entry per registered device).
   *
   * @param peerId - The target user's identifier.
   * @throws {Error} If the server request fails or the peer has no registered keys.
   */
  const fetchPeerDeviceKeys = useCallback(
    async (peerId: string): Promise<DeviceKey[]> => {
      const cached   = peerKeyCacheRef.current.get(peerId)
      const cachedAt = peerKeyCacheTimeRef.current.get(peerId) ?? 0
      if (cached && Date.now() - cachedAt < PEER_KEY_TTL_MS) return cached

      const res = await fetch(`${httpBase}/v1/keys/${peerId}`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      })
      if (!res.ok) {
        throw new Error(
          `Could not fetch public keys for '${peerId}': ${res.status}. ` +
          `Make sure ${peerId} has registered.`
        )
      }
      const { devices } = (await res.json()) as {
        userId:  string
        devices: Array<{ deviceId: string; publicKey: string }>
      }
      const deviceKeys: DeviceKey[] = devices.map((d) => ({
        deviceId:  d.deviceId,
        publicKey: importKey(d.publicKey),
      }))
      peerKeyCacheRef.current.set(peerId, deviceKeys)
      peerKeyCacheTimeRef.current.set(peerId, Date.now())
      return deviceKeys
    },
    [apiKey, httpBase]
  )

  // ── X3DH prekey management ──────────────────────────────────────────────────

  /**
   * Publish identity + signed prekey (idempotent) plus any supplied one-time
   * prekeys. Best-effort: a failure is surfaced via `onError` but does not abort
   * the connection — peers just can't open new sessions until it lands.
   */
  const publishPreKeys = useCallback(
    async (oneTimePreKeys: Array<{ keyId: number; publicKey: string }>): Promise<void> => {
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
            oneTimePreKeys,
          }),
        })
        if (!res.ok) onErrorRef.current?.(new Error(`Prekey publish failed: ${res.status}`))
      } catch (err) {
        onErrorRef.current?.(err instanceof Error ? err : new Error('Prekey publish failed.'))
      }
    },
    [apiKey, httpBase, userId]
  )

  /**
   * Restore or generate this device's identity key, signed prekey, and one-time
   * prekey pool, then publish the public material to the key server.
   */
  const initPreKeys = useCallback(async (): Promise<void> => {
    // Shared with useE2EPresence via ratchetStore so both hooks converge on one
    // generation per userId (avoids racing identity/signed-prekey publishes).
    const { prekeys, created } = await loadOrCreatePreKeys(userId)
    prekeysRef.current  = prekeys
    identityRef.current = {
      publicKey:  importKey(prekeys.identityPub),
      privateKey: importKey(prekeys.identityPriv),
    }
    // Publish the full one-time prekey pool only when we just created it.
    // On restore, re-assert identity + signed prekey but don't re-publish
    // existing one-time prekeys — some may already be reserved by senders.
    await publishPreKeys(
      created ? prekeys.oneTimePreKeys.map((o) => ({ keyId: o.keyId, publicKey: o.pub })) : [],
    )
  }, [userId, publishPreKeys])

  /** Fetch a peer device's prekey bundle (consumes one of their one-time prekeys). */
  const fetchPreKeyBundle = useCallback(
    async (peerId: string, deviceId: string): Promise<PreKeyBundle> => {
      const res = await fetch(
        `${httpBase}/v1/prekeys/${encodeURIComponent(peerId)}/${encodeURIComponent(deviceId)}`,
        { headers: { Authorization: `Bearer ${apiKey}` } },
      )
      if (!res.ok) {
        throw new Error(
          `Could not fetch prekey bundle for '${peerId}' device '${deviceId}': ${res.status}. ` +
          `Make sure ${peerId} has published prekeys.`,
        )
      }
      return (await res.json()) as PreKeyBundle
    },
    [apiKey, httpBase]
  )

  /** Top the one-time prekey pool back up to OTP_POOL_SIZE and publish the new keys. */
  const replenishOneTimePreKeys = useCallback(async (): Promise<void> => {
    const pk = prekeysRef.current
    if (!identityRef.current || !pk) return
    const need = OTP_POOL_SIZE - pk.oneTimePreKeys.length
    if (need <= 0) return

    const fresh = await generateOneTimePreKeys(pk.nextOtpId, need)
    pk.nextOtpId += need
    for (const o of fresh) {
      pk.oneTimePreKeys.push({ keyId: o.keyId, pub: exportKey(o.keyPair.publicKey), priv: exportKey(o.keyPair.privateKey) })
    }
    await savePreKeys(userId, pk)
    await publishPreKeys(fresh.map((o) => ({ keyId: o.keyId, publicKey: exportKey(o.keyPair.publicKey) })))
  }, [userId, publishPreKeys])

  /** Remove a consumed one-time prekey from the local pool and replenish if low. */
  const consumeOneTimePreKey = useCallback(
    async (keyId: number): Promise<void> => {
      const pk = prekeysRef.current
      if (!pk) return
      pk.oneTimePreKeys = pk.oneTimePreKeys.filter((o) => o.keyId !== keyId)
      await savePreKeys(userId, pk)
      if (pk.oneTimePreKeys.length <= OTP_LOW_WATER) await replenishOneTimePreKeys()
    },
    [userId, replenishOneTimePreKeys]
  )

  /**
   * Returns the sender ratchet for a specific peer device, restoring it from
   * IndexedDB if available or initialising a new one on first contact.
   *
   * Ratchet state key: `s:${peerId}:${device.deviceId}`
   *
   * @param peerId - Recipient user ID.
   * @param device - The specific recipient device (from `fetchPeerDeviceKeys`).
   */
  const getOrInitSenderRatchet = useCallback(
    async (peerId: string, deviceId: string): Promise<DoubleRatchet> => {
      const key      = `s:${peerId}:${deviceId}`
      const existing = ratchetsRef.current.get(key)
      if (existing) return existing

      const stored = await loadRatchet(userId, key)
      if (stored) {
        const ratchet = await DoubleRatchet.fromExport(stored)
        ratchetsRef.current.set(key, ratchet)
        return ratchet
      }

      const myIdentity = identityRef.current
      if (!myIdentity) throw new Error('Identity key not initialised.')

      // New outbound session: fetch the peer device's prekey bundle and run
      // X3DH. x3dhInitiate verifies the signed-prekey signature and aborts on
      // mismatch (MITM guard).
      const bundle  = await fetchPreKeyBundle(peerId, deviceId)
      const init    = await x3dhInitiate(myIdentity, bundle)
      const ratchet = await DoubleRatchet.initSender(init.sessionKeys, init.signedPreKeyPublic)
      ratchetsRef.current.set(key, ratchet)
      // Carry the prekey message on outgoing frames until the peer replies.
      pendingPrekeyRef.current.set(`${peerId}:${deviceId}`, init.message)
      await saveRatchet(userId, key, ratchet.export())
      return ratchet
    },
    [userId, fetchPreKeyBundle]
  )

  /**
   * Returns the receiver ratchet for a specific sender device, restoring it
   * from IndexedDB if available or initialising a new one on first contact.
   *
   * Ratchet state key: `r:${peerId}:${fromDeviceId}`
   *
   * @param peerId       - Sender user ID.
   * @param fromDeviceId - Sender's device UUID (from the wire message).
   */
  const getOrInitReceiverRatchet = useCallback(
    async (peerId: string, fromDeviceId: string, prekey?: PreKeyMessage): Promise<DoubleRatchet> => {
      const key      = `r:${peerId}:${fromDeviceId}`
      const existing = ratchetsRef.current.get(key)
      if (existing) return existing

      const stored = await loadRatchet(userId, key)
      if (stored) {
        const ratchet = await DoubleRatchet.fromExport(stored)
        ratchetsRef.current.set(key, ratchet)
        return ratchet
      }

      const myIdentity = identityRef.current
      const pk         = prekeysRef.current
      if (!myIdentity || !pk) throw new Error('Prekeys not initialised.')
      // A brand-new inbound session can only be established from an X3DH prekey
      // message. Without it we cannot derive the shared secret.
      if (!prekey) {
        throw new DecryptionFailedError(
          `No session with '${peerId}' device '${fromDeviceId}' and no prekey message to establish one.`,
        )
      }

      if (prekey.signedPreKeyId !== pk.signedPreKey.keyId) {
        throw new DecryptionFailedError(
          `Signed prekey ${prekey.signedPreKeyId} is no longer available (current is ${pk.signedPreKey.keyId}).`,
        )
      }
      const signedPair: KeyPair = {
        publicKey:  importKey(pk.signedPreKey.pub),
        privateKey: importKey(pk.signedPreKey.priv),
      }
      let oneTimePair: KeyPair | null = null
      if (prekey.oneTimePreKeyId !== null) {
        const found = pk.oneTimePreKeys.find((o) => o.keyId === prekey.oneTimePreKeyId)
        if (!found) throw new DecryptionFailedError(`One-time prekey ${prekey.oneTimePreKeyId} not found locally.`)
        oneTimePair = { publicKey: importKey(found.pub), privateKey: importKey(found.priv) }
      }

      const keys    = await x3dhRespond(myIdentity, signedPair, oneTimePair, prekey)
      const ratchet = await DoubleRatchet.initReceiver(keys, signedPair)
      ratchetsRef.current.set(key, ratchet)
      // The one-time prekey is now spent — remove it locally and replenish if low.
      if (prekey.oneTimePreKeyId !== null) await consumeOneTimePreKey(prekey.oneTimePreKeyId)
      await saveRatchet(userId, key, ratchet.export())
      return ratchet
    },
    [userId, consumeOneTimePreKey]
  )

  useEffect(() => {
    let cancelled    = false
    let retryCount   = 0
    let retryTimeout: ReturnType<typeof setTimeout> | null = null
    let ws: WebSocket | null = null

    function scheduleReconnect() {
      if (cancelled) return
      const base  = Math.min(BACKOFF_BASE_MS * Math.pow(2, retryCount++), BACKOFF_MAX_MS)
      const delay = base * (0.75 + Math.random() * 0.5)
      setIsConnecting(true)
      retryTimeout = setTimeout(() => {
        if (!cancelled) connectWS()
      }, delay)
    }

    function connectWS() {
      ws = new WebSocket(`${wsBase}/v1/relay`)
      socketRef.current = ws

      ws.addEventListener('open', () => {
        ws!.send(JSON.stringify({ type: 'auth', token: apiKey }))
        ws!.send(JSON.stringify({ type: 'register', userId, deviceId: deviceIdRef.current }))
        retryCount = 0
        if (!cancelled) { setIsReady(true); setIsConnecting(false) }
      })

      ws.addEventListener('message', async (event) => {
        let msg: WireMessage
        try {
          msg = JSON.parse(event.data as string) as WireMessage
        } catch { return }

        if (
          msg.type !== 'message' ||
          !msg.from ||
          !msg.fromDeviceId ||
          !msg.ciphertext ||
          !msg.nonce ||
          !msg.encHeader
        ) return

        onWireMessageRef.current?.({
          direction:  'received',
          ciphertext: msg.ciphertext,
          nonce:      msg.nonce,
          timestamp:  Date.now(),
        })

        try {
          const ratchet = await getOrInitReceiverRatchet(msg.from, msg.fromDeviceId, msg.prekey)
          const text = await ratchet.decrypt({
            encHeader:  importKey(msg.encHeader),
            ciphertext: importKey(msg.ciphertext),
            nonce:      importKey(msg.nonce),
          })
          await saveRatchet(userId, `r:${msg.from}:${msg.fromDeviceId}`, ratchet.export())
          // We've heard from this peer device — stop attaching our prekey message.
          pendingPrekeyRef.current.delete(`${msg.from}:${msg.fromDeviceId}`)
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

        // Get or create a stable device ID for this browser/device
        const deviceId = await getOrCreateDeviceId(userId)
        deviceIdRef.current = deviceId

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

        // Register public key + deviceId with the HTTP server (idempotent upsert)
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

        // Set up X3DH prekeys (identity key, signed prekey, one-time prekey
        // pool) and publish them so peers can open sessions asynchronously.
        await initPreKeys()

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
      identityRef.current = null
      prekeysRef.current = null
      ratchetsRef.current.clear()
      pendingPrekeyRef.current.clear()
      peerKeyCacheRef.current.clear()
      peerKeyCacheTimeRef.current.clear()
    }
  }, [apiKey, userId, httpBase, wsBase, getOrInitReceiverRatchet, initPreKeys])

  /**
   * Encrypts `text` and delivers it to every registered device of `to`.
   * Each device gets its own Double Ratchet envelope so messages decrypt
   * independently regardless of which device the recipient opens them on.
   *
   * @param to   - Recipient user ID.
   * @param text - Plaintext message to send.
   * @throws {Error} If the WebSocket is not connected or the recipient has no keys.
   */
  const sendMessage = useCallback(
    async (to: string, text: string): Promise<void> => {
      const socket = socketRef.current
      if (!socket || socket.readyState !== WebSocket.OPEN) {
        throw new Error('WebSocket is not connected. Wait for isReady to be true.')
      }

      // Fetch all of the recipient's registered devices
      const peerDevices = await fetchPeerDeviceKeys(to)
      if (peerDevices.length === 0) {
        throw new Error(`No devices found for '${to}'. Make sure they have registered.`)
      }

      // Send one encrypted message per recipient device
      for (const device of peerDevices) {
        const ratchet = await getOrInitSenderRatchet(to, device.deviceId)
        const { encHeader, ciphertext, nonce } = await ratchet.encrypt(text)
        await saveRatchet(userId, `s:${to}:${device.deviceId}`, ratchet.export())

        // Attach the X3DH prekey message until we hear back from this device, so
        // the recipient can establish the session even if earlier frames were lost.
        const pending = pendingPrekeyRef.current.get(`${to}:${device.deviceId}`)

        const ctB64 = exportKey(ciphertext)
        const nB64  = exportKey(nonce)
        const ehB64 = exportKey(encHeader)

        socket.send(JSON.stringify({
          type:       'message',
          to,
          toDeviceId: device.deviceId,
          ciphertext: ctB64,
          nonce:      nB64,
          encHeader:  ehB64,
          ...(pending && { prekey: pending }),
        }))

        onWireMessageRef.current?.({
          direction:  'sent',
          ciphertext: ctB64,
          nonce:      nB64,
          timestamp:  Date.now(),
        })
      }

      // Add sent message to local state once (not once per device)
      setMessages((prev) => {
        const next   = [...prev, { from: userId, text, timestamp: Date.now() }]
        const capped = next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next
        void saveMessages(userId, capped)
        return capped
      })
    },
    [userId, fetchPeerDeviceKeys, getOrInitSenderRatchet]
  )

  return { messages, isReady, isConnecting, sendMessage, error }
}
