import {
  generateKeyPair,
  exportKey,
  importKey,
  sodiumReady,
  DecryptionFailedError,
  DoubleRatchet,
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  buildPreKeyBundle,
  x3dhInitiate,
  x3dhRespond,
  encryptField as coreEncryptField,
  decryptField as coreDecryptField,
  generateFieldKey as coreGenerateFieldKey,
} from '@encra/core'
import type { KeyPair, IdentityKeyPair, PreKeyBundle, PreKeyMessage, EncryptedField } from '@encra/core'

export type { EncryptedField }
import {
  loadKeyPair,   saveKeyPair,
  loadRatchet,   saveRatchet,
  loadMessages,  saveMessages,
  loadPreKeys,   savePreKeys,
  getOrCreateDeviceId,
  type StoredPreKeys,
} from './ratchetStore.js'

// ── Public types ──────────────────────────────────────────────────────────────

export interface Message {
  from:      string
  text:      string
  timestamp: number
}

/**
 * A single device's public key entry.
 * Returned by `GET /v1/keys/:userId` as an array (one entry per registered device).
 */
export interface DeviceKey {
  /** Stable UUID generated once per browser/device, stored in IndexedDB. */
  deviceId:  string
  publicKey: Uint8Array
}

/**
 * An encrypted file produced by `encryptFile`.
 * Contains one encrypted copy per recipient device.
 * Transmit the entire object — the recipient's device picks its own entry.
 */
export interface EncryptedFile {
  /** Original filename (e.g. `"photo.jpg"`). Stored as plaintext metadata. */
  name:     string
  /** MIME type (e.g. `"image/jpeg"`). Stored as plaintext metadata. */
  mimeType: string
  /** Original file size in bytes (pre-encryption). */
  size:     number
  /**
   * One encrypted copy per registered device of the recipient.
   * Each entry uses a unique nonce.
   */
  devices: Array<{
    /** Matches the recipient device's `deviceId` in IndexedDB. */
    deviceId:   string
    ciphertext: Uint8Array
    nonce:      Uint8Array
  }>
}

/**
 * Encrypted form fields produced by `encryptFields`.
 * Contains one independently-encrypted copy per recipient device.
 */
export interface EncryptedFields {
  /**
   * One encrypted copy per registered device of the recipient.
   * Each device entry has independent per-field nonces.
   */
  devices: Array<{
    deviceId: string
    fields:   Record<string, { ciphertext: string; nonce: string }>
  }>
}

export interface WireEvent {
  direction:  'sent' | 'received'
  ciphertext: string
  nonce:      string
  timestamp:  number
}

export interface EncraClientOptions {
  apiKey:     string
  userId:     string
  /** Defaults to the Encra managed server. */
  serverUrl?: string
}

// ── Typed event map ───────────────────────────────────────────────────────────

interface EventMap {
  ready:        []
  connecting:   []
  disconnected: []
  message:      [msg: Message]
  error:        [err: Error]
  wire:         [event: WireEvent]
}

type Listener<K extends keyof EventMap> = (...args: EventMap[K]) => void

// ── Internal wire shape ───────────────────────────────────────────────────────

/**
 * A message on the wire. `encHeader` is the ratchet header encrypted under the
 * sending header key (the relay never sees the ratchet public key or counters).
 * `prekey` carries the X3DH prekey message on a session's first inbound
 * message(s) so the recipient can establish the session; it travels alongside
 * the encrypted header because it must be readable before any header key exists.
 */
interface WireMessage {
  type:          string
  from?:         string
  fromDeviceId?: string
  ciphertext?:   string
  nonce?:        string
  encHeader?:    string
  prekey?:       PreKeyMessage
}

const BACKOFF_BASE_MS    = 1_000
const BACKOFF_MAX_MS     = 60_000
const MAX_MESSAGES       = 200
const PEER_KEY_TTL_MS    = 5 * 60 * 1_000   // 5 minutes — re-fetch to pick up new devices
const ENCRA_SERVER_URL   = 'https://api.encra.dev'

/** Number of one-time prekeys to publish when first registering. */
const OTP_POOL_SIZE      = 100
/** Replenish the one-time prekey pool when it drops to this many or fewer. */
const OTP_LOW_WATER      = 20

/** Maximum file size accepted by `encryptFile` (50 MB). */
export const MAX_FILE_BYTES = 50 * 1024 * 1024

// ── EncraClient ───────────────────────────────────────────────────────────────

/**
 * Framework-agnostic Encra client with multi-device support.
 *
 * Each browser/device gets a stable `deviceId` stored in IndexedDB.
 * When sending to a recipient, encrypts once per registered device so all
 * their devices can decrypt. Ratchet state is per-device-pair so sessions
 * are fully independent across devices.
 *
 * @example
 * const client = new EncraClient({ apiKey: 'e2e_live_xxx', userId: 'alice' })
 * client.on('message', (msg) => console.log(msg.from, msg.text))
 * client.on('ready',   ()    => console.log('connected'))
 * await client.connect()
 * await client.sendMessage('bob', 'hello!')
 * client.disconnect()
 */
export class EncraClient {
  // ── State ─────────────────────────────────────────────────────────────────

  private _messages:     Message[]  = []
  private _isReady:      boolean    = false
  private _isConnecting: boolean    = false
  private _error:        Error|null = null

  private _keyPair:          KeyPair | null                        = null
  private _identity:         IdentityKeyPair | null                = null
  private _prekeys:          StoredPreKeys | null                  = null
  private _deviceId:         string | null                         = null
  private _ratchets:         Map<string, DoubleRatchet>            = new Map()
  /** Pending X3DH prekey messages, keyed `${peerId}:${deviceId}` (sender side). */
  private _pendingPrekey:    Map<string, PreKeyMessage>            = new Map()
  private _peerKeyCache:     Map<string, DeviceKey[]>              = new Map()
  private _peerKeyCacheTime: Map<string, number>                   = new Map()
  private _socket:       WebSocket | null              = null
  private _retryCount:   number                        = 0
  private _retryTimer:   ReturnType<typeof setTimeout>|null = null
  private _cancelled:    boolean                       = false
  private _connected:    boolean                       = false

  private readonly _listeners = new Map<string, Listener<keyof EventMap>[]>()

  // ── Options ───────────────────────────────────────────────────────────────

  private readonly _apiKey:   string
  private readonly _userId:   string
  private readonly _httpBase: string
  private readonly _wsBase:   string

  constructor({ apiKey, userId, serverUrl = ENCRA_SERVER_URL }: EncraClientOptions) {
    this._apiKey   = apiKey
    this._userId   = userId
    this._httpBase = serverUrl.replace(/\/$/, '')
    this._wsBase   = this._httpBase.replace(/^http/, 'ws')
  }

  // ── Getters ───────────────────────────────────────────────────────────────

  get isReady():      boolean    { return this._isReady }
  get isConnecting(): boolean    { return this._isConnecting }
  get error():        Error|null { return this._error }
  get messages():     Message[]  { return this._messages }
  /** This device's stable ID (available after `connect()` resolves). */
  get deviceId():     string | null { return this._deviceId }

  // ── Typed event emitter ───────────────────────────────────────────────────

  on<K extends keyof EventMap>(event: K, listener: Listener<K>): this {
    const list = (this._listeners.get(event) ?? []) as Listener<K>[]
    list.push(listener)
    this._listeners.set(event, list as Listener<keyof EventMap>[])
    return this
  }

  off<K extends keyof EventMap>(event: K, listener: Listener<K>): this {
    const list = (this._listeners.get(event) ?? []) as Listener<K>[]
    this._listeners.set(
      event,
      list.filter((l) => l !== listener) as Listener<keyof EventMap>[]
    )
    return this
  }

  private _emit<K extends keyof EventMap>(event: K, ...args: EventMap[K]): void {
    const list = (this._listeners.get(event) ?? []) as Listener<K>[]
    list.forEach((l) => l(...args))
  }

  // ── Public API ────────────────────────────────────────────────────────────

  async connect(): Promise<void> {
    if (this._connected) return
    this._connected = true
    await this._init()
  }

  disconnect(): void {
    this._cancelled = true
    if (this._retryTimer) clearTimeout(this._retryTimer)
    this._socket?.close()
    this._socket       = null
    this._keyPair      = null
    this._identity     = null
    this._prekeys      = null
    this._ratchets.clear()
    this._pendingPrekey.clear()
    this._peerKeyCache.clear()
    this._peerKeyCacheTime.clear()
    this._setReady(false)
    this._setConnecting(false)
  }

  /**
   * Encrypt `text` and send it to all registered devices of `to`.
   * Throws if the WebSocket is not open.
   */
  async sendMessage(to: string, text: string): Promise<void> {
    if (!this._socket || this._socket.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected. Wait for the "ready" event before sending.')
    }

    const peerDevices = await this._fetchPeerDeviceKeys(to)

    for (const device of peerDevices) {
      const ratchet     = await this._getOrInitSenderRatchet(to, device.deviceId)
      const { encHeader, ciphertext, nonce } = await ratchet.encrypt(text)
      await saveRatchet(this._userId, `s:${to}:${device.deviceId}`, ratchet.export())

      // Attach the X3DH prekey message until we hear back from this device, so
      // the recipient can establish the session even if earlier frames were lost.
      const pending = this._pendingPrekey.get(`${to}:${device.deviceId}`)

      const ctB64  = exportKey(ciphertext)
      const nB64   = exportKey(nonce)
      const ehB64  = exportKey(encHeader)

      this._socket.send(JSON.stringify({
        type: 'message', to, toDeviceId: device.deviceId,
        ciphertext: ctB64, nonce: nB64, encHeader: ehB64,
        ...(pending && { prekey: pending }),
      }))

      this._emit('wire', { direction: 'sent', ciphertext: ctB64, nonce: nB64, timestamp: Date.now() })
    }

    this._addMessage({ from: this._userId, text, timestamp: Date.now() })
  }

  /**
   * Encrypt a `File` or `Blob` for all registered devices of `to`.
   * Returns an `EncryptedFile` with one encrypted copy per device.
   * The recipient's device automatically picks its own copy when decrypting.
   *
   * @throws {RangeError} If the file exceeds `MAX_FILE_BYTES` (50 MB).
   */
  async encryptFile(file: File | Blob, to: string): Promise<EncryptedFile> {
    if (!this._keyPair) throw new Error('EncraClient is not connected. Call connect() first.')
    if (file.size > MAX_FILE_BYTES) {
      throw new RangeError(
        `File too large: ${file.size} bytes exceeds the ${MAX_FILE_BYTES}-byte limit.`
      )
    }

    const peerDevices = await this._fetchPeerDeviceKeys(to)
    const bytes       = await EncraClient._readFileBytes(file)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready

    const deviceEntries: EncryptedFile['devices'] = []

    for (const device of peerDevices) {
      const shared     = sodium.crypto_box_beforenm(device.publicKey.slice(), this._keyPair.privateKey.slice())
      const nonce      = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
      const ciphertext = sodium.crypto_secretbox_easy(bytes, nonce, shared)
      deviceEntries.push({ deviceId: device.deviceId, ciphertext, nonce })
    }

    return {
      name:     file instanceof File ? file.name : 'file',
      mimeType: file.type || 'application/octet-stream',
      size:     file.size,
      devices:  deviceEntries,
    }
  }

  /**
   * Decrypt an `EncryptedFile` received from `from`.
   * Automatically selects the entry encrypted for this device.
   *
   * @throws {DecryptionFailedError} If no entry matches this device or decryption fails.
   */
  async decryptFile(encrypted: EncryptedFile, from: string): Promise<File> {
    if (!this._keyPair || !this._deviceId) {
      throw new Error('EncraClient is not connected. Call connect() first.')
    }

    const entry = encrypted.devices.find((d) => d.deviceId === this._deviceId)
    if (!entry) {
      throw new DecryptionFailedError(
        `decryptFile: no entry found for this device (${this._deviceId}).`
      )
    }

    // _fetchPeerDeviceKeys throws if the user has no keys registered
    const peerDevices = await this._fetchPeerDeviceKeys(from)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready

    // Try each sender device key until one decrypts successfully
    for (const senderDev of peerDevices) {
      const shared = sodium.crypto_box_beforenm(senderDev.publicKey.slice(), this._keyPair.privateKey.slice())
      let plainBytes: Uint8Array
      try {
        plainBytes = sodium.crypto_secretbox_open_easy(
          entry.ciphertext.slice(),
          entry.nonce.slice(),
          shared,
        )
      } catch {
        continue
      }
      const buf = plainBytes.buffer.slice(
        plainBytes.byteOffset,
        plainBytes.byteOffset + plainBytes.byteLength,
      ) as ArrayBuffer
      return new File([buf], encrypted.name, { type: encrypted.mimeType })
    }

    throw new DecryptionFailedError(`decryptFile: decryption failed for file "${encrypted.name}".`)
  }

  /**
   * Encrypt a flat object of string field values for all registered devices of `to`.
   * Each device gets independently encrypted fields with unique random nonces.
   *
   * @throws {TypeError} If any field value is not a string.
   */
  async encryptFields(
    fields: Record<string, string>,
    to: string,
  ): Promise<EncryptedFields> {
    if (!this._keyPair) throw new Error('EncraClient is not connected. Call connect() first.')
    if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) {
      throw new TypeError('encryptFields: fields must be a plain object of string values.')
    }

    const peerDevices = await this._fetchPeerDeviceKeys(to)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready
    const B64 = sodium.base64_variants.URLSAFE_NO_PADDING

    const deviceEntries: EncryptedFields['devices'] = []

    for (const device of peerDevices) {
      const shared  = sodium.crypto_box_beforenm(device.publicKey.slice(), this._keyPair.privateKey.slice())
      const encryptedFields: Record<string, { ciphertext: string; nonce: string }> = {}

      for (const [key, value] of Object.entries(fields)) {
        if (typeof value !== 'string') {
          throw new TypeError(`encryptFields: field "${key}" must be a string, got ${typeof value}.`)
        }
        const nonce      = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        const ciphertext = sodium.crypto_secretbox_easy(value, nonce, shared)
        encryptedFields[key] = {
          ciphertext: sodium.to_base64(ciphertext, B64),
          nonce:      sodium.to_base64(nonce, B64),
        }
      }

      deviceEntries.push({ deviceId: device.deviceId, fields: encryptedFields })
    }

    return { devices: deviceEntries }
  }

  /**
   * Decrypt an `EncryptedFields` object received from `from`.
   * Automatically selects the entry encrypted for this device.
   *
   * @throws {DecryptionFailedError} If no entry matches this device or any field fails to decrypt.
   */
  async decryptFields(
    encrypted: EncryptedFields,
    from: string,
  ): Promise<Record<string, string>> {
    if (!this._keyPair || !this._deviceId) {
      throw new Error('EncraClient is not connected. Call connect() first.')
    }

    const entry = encrypted.devices.find((d) => d.deviceId === this._deviceId)
    if (!entry) {
      throw new DecryptionFailedError(
        `decryptFields: no entry found for this device (${this._deviceId}).`
      )
    }

    const peerDevices = await this._fetchPeerDeviceKeys(from)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready
    const B64 = sodium.base64_variants.URLSAFE_NO_PADDING

    // Try each sender device key
    for (const senderDev of peerDevices) {
      const shared  = sodium.crypto_box_beforenm(senderDev.publicKey.slice(), this._keyPair.privateKey.slice())
      const result: Record<string, string> = {}
      let allOk = true

      for (const [key, { ciphertext, nonce }] of Object.entries(entry.fields)) {
        let ctBytes: Uint8Array
        let nonceBytes: Uint8Array
        try {
          ctBytes    = sodium.from_base64(ciphertext, B64)
          nonceBytes = sodium.from_base64(nonce, B64)
        } catch {
          allOk = false; break
        }
        let plainBytes: Uint8Array
        try {
          plainBytes = sodium.crypto_secretbox_open_easy(ctBytes, nonceBytes, shared)
        } catch {
          allOk = false; break
        }
        result[key] = sodium.to_string(plainBytes)
      }

      if (allOk) return result
    }

    throw new DecryptionFailedError('decryptFields: decryption failed — wrong key or tampered data.')
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private static _readFileBytes(file: File | Blob): Promise<Uint8Array> {
    if (typeof file.arrayBuffer === 'function') {
      return file.arrayBuffer().then((buf) => new Uint8Array(buf))
    }
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload  = () => resolve(new Uint8Array(reader.result as ArrayBuffer))
      reader.onerror = () => reject(reader.error ?? new Error('FileReader error'))
      reader.readAsArrayBuffer(file)
    })
  }

  private _setReady(v: boolean)      { this._isReady      = v; if (v) this._emit('ready') }
  private _setConnecting(v: boolean) { this._isConnecting = v; if (v) this._emit('connecting') }

  private _addMessage(msg: Message): void {
    const next = [...this._messages, msg]
    this._messages = next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next
    void saveMessages(this._userId, this._messages)
    this._emit('message', msg)
  }

  /** Fetch all device keys for a peer, with a 5-minute TTL cache. */
  private async _fetchPeerDeviceKeys(peerId: string): Promise<DeviceKey[]> {
    const cached    = this._peerKeyCache.get(peerId)
    const cachedAt  = this._peerKeyCacheTime.get(peerId) ?? 0
    if (cached && Date.now() - cachedAt < PEER_KEY_TTL_MS) return cached

    const res = await fetch(`${this._httpBase}/v1/keys/${peerId}`, {
      headers: { Authorization: `Bearer ${this._apiKey}` },
    })
    if (!res.ok) {
      throw new Error(
        `Could not fetch public keys for '${peerId}': ${res.status}. ` +
        `Make sure ${peerId} has registered.`
      )
    }
    const { devices } = (await res.json()) as {
      devices: Array<{ deviceId: string; publicKey: string }>
    }
    const keys: DeviceKey[] = devices.map((d) => ({
      deviceId:  d.deviceId,
      publicKey: importKey(d.publicKey),
    }))
    this._peerKeyCache.set(peerId, keys)
    this._peerKeyCacheTime.set(peerId, Date.now())
    return keys
  }

  private async _getOrInitSenderRatchet(peerId: string, deviceId: string): Promise<DoubleRatchet> {
    const ratchetKey = `s:${peerId}:${deviceId}`
    const existing   = this._ratchets.get(ratchetKey)
    if (existing) return existing

    const stored = await loadRatchet(this._userId, ratchetKey)
    if (stored) {
      const ratchet = await DoubleRatchet.fromExport(stored)
      this._ratchets.set(ratchetKey, ratchet)
      return ratchet
    }

    if (!this._identity) throw new Error('Identity key not initialised.')

    // New outbound session: fetch the peer device's prekey bundle and run X3DH.
    // x3dhInitiate verifies the signed-prekey signature and aborts on mismatch.
    const bundle = await this._fetchPreKeyBundle(peerId, deviceId)
    const init   = await x3dhInitiate(this._identity, bundle)
    const ratchet = await DoubleRatchet.initSender(init.sessionKeys, init.signedPreKeyPublic)
    this._ratchets.set(ratchetKey, ratchet)
    // Carry the prekey message on outgoing frames until the peer replies.
    this._pendingPrekey.set(`${peerId}:${deviceId}`, init.message)
    await saveRatchet(this._userId, ratchetKey, ratchet.export())
    return ratchet
  }

  private async _getOrInitReceiverRatchet(
    peerId:       string,
    fromDeviceId: string,
    prekey?:      PreKeyMessage,
  ): Promise<DoubleRatchet> {
    const ratchetKey = `r:${peerId}:${fromDeviceId}`
    const existing   = this._ratchets.get(ratchetKey)
    if (existing) return existing

    const stored = await loadRatchet(this._userId, ratchetKey)
    if (stored) {
      const ratchet = await DoubleRatchet.fromExport(stored)
      this._ratchets.set(ratchetKey, ratchet)
      return ratchet
    }

    if (!this._identity || !this._prekeys) throw new Error('Prekeys not initialised.')
    // A brand-new inbound session can only be established from an X3DH prekey
    // message. Without it we cannot derive the shared secret.
    if (!prekey) {
      throw new DecryptionFailedError(
        `No session with '${peerId}' device '${fromDeviceId}' and no prekey message to establish one.`,
      )
    }

    const { signedPair, oneTimePair } = this._resolveResponderKeys(prekey)
    const keys    = await x3dhRespond(this._identity, signedPair, oneTimePair, prekey)
    const ratchet = await DoubleRatchet.initReceiver(keys, signedPair)
    this._ratchets.set(ratchetKey, ratchet)
    // The one-time prekey is now spent — remove it locally and replenish if low.
    if (prekey.oneTimePreKeyId !== null) {
      await this._consumeOneTimePreKey(prekey.oneTimePreKeyId)
    }
    await saveRatchet(this._userId, ratchetKey, ratchet.export())
    return ratchet
  }

  // ── X3DH prekey management ──────────────────────────────────────────────────

  /**
   * Restore or generate this device's identity key, signed prekey, and
   * one-time prekey pool, then publish the public material to the key server.
   */
  private async _initPreKeys(): Promise<void> {
    const stored = await loadPreKeys(this._userId)
    if (stored) {
      this._prekeys  = stored
      this._identity = {
        publicKey:  importKey(stored.identityPub),
        privateKey: importKey(stored.identityPriv),
      }
      // Re-assert identity + signed prekey (idempotent upserts). Don't re-publish
      // existing one-time prekeys — some may already be reserved by senders.
      await this._publishPreKeys([])
      return
    }

    const identity = await generateIdentityKeyPair()
    const spk      = await generateSignedPreKey(identity, 1)
    const otps     = await generateOneTimePreKeys(1, OTP_POOL_SIZE)

    this._identity = identity
    this._prekeys  = {
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
    await savePreKeys(this._userId, this._prekeys)
    await this._publishPreKeys(this._prekeys.oneTimePreKeys.map((o) => ({ keyId: o.keyId, publicKey: o.pub })))
  }

  /**
   * Publish identity + signed prekey (idempotent) plus any supplied one-time
   * prekeys. Best-effort: a failure is surfaced as an `error` event but does not
   * abort the connection — peers simply can't open new sessions until it lands.
   */
  private async _publishPreKeys(
    oneTimePreKeys: Array<{ keyId: number; publicKey: string }>,
  ): Promise<void> {
    if (!this._prekeys || !this._deviceId) return
    const pk = this._prekeys
    try {
      const res = await fetch(`${this._httpBase}/v1/prekeys`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this._apiKey}` },
        body:    JSON.stringify({
          userId:       this._userId,
          deviceId:     this._deviceId,
          identityKey:  pk.identityPub,
          signedPreKey: {
            keyId:     pk.signedPreKey.keyId,
            publicKey: pk.signedPreKey.pub,
            signature: pk.signedPreKey.signature,
          },
          oneTimePreKeys,
        }),
      })
      if (!res.ok) {
        this._emit('error', new Error(`Prekey publish failed: ${res.status}`))
      }
    } catch (err) {
      this._emit('error', err instanceof Error ? err : new Error('Prekey publish failed.'))
    }
  }

  /** Fetch a peer device's prekey bundle (consumes one of their one-time prekeys). */
  private async _fetchPreKeyBundle(peerId: string, deviceId: string): Promise<PreKeyBundle> {
    const res = await fetch(`${this._httpBase}/v1/prekeys/${encodeURIComponent(peerId)}/${encodeURIComponent(deviceId)}`, {
      headers: { Authorization: `Bearer ${this._apiKey}` },
    })
    if (!res.ok) {
      throw new Error(
        `Could not fetch prekey bundle for '${peerId}' device '${deviceId}': ${res.status}. ` +
        `Make sure ${peerId} has published prekeys.`,
      )
    }
    return (await res.json()) as PreKeyBundle
  }

  /** Resolve the local private prekeys a prekey message refers to (responder side). */
  private _resolveResponderKeys(prekey: PreKeyMessage): { signedPair: KeyPair; oneTimePair: KeyPair | null } {
    const pk = this._prekeys!
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
      if (!found) {
        throw new DecryptionFailedError(`One-time prekey ${prekey.oneTimePreKeyId} not found locally.`)
      }
      oneTimePair = { publicKey: importKey(found.pub), privateKey: importKey(found.priv) }
    }
    return { signedPair, oneTimePair }
  }

  /** Remove a consumed one-time prekey from the local pool and replenish if low. */
  private async _consumeOneTimePreKey(keyId: number): Promise<void> {
    if (!this._prekeys) return
    this._prekeys.oneTimePreKeys = this._prekeys.oneTimePreKeys.filter((o) => o.keyId !== keyId)
    await savePreKeys(this._userId, this._prekeys)
    if (this._prekeys.oneTimePreKeys.length <= OTP_LOW_WATER) {
      await this._replenishOneTimePreKeys()
    }
  }

  /** Top the one-time prekey pool back up to OTP_POOL_SIZE and publish the new keys. */
  private async _replenishOneTimePreKeys(): Promise<void> {
    if (!this._identity || !this._prekeys) return
    const need = OTP_POOL_SIZE - this._prekeys.oneTimePreKeys.length
    if (need <= 0) return

    const fresh = await generateOneTimePreKeys(this._prekeys.nextOtpId, need)
    this._prekeys.nextOtpId += need
    for (const o of fresh) {
      this._prekeys.oneTimePreKeys.push({
        keyId: o.keyId,
        pub:   exportKey(o.keyPair.publicKey),
        priv:  exportKey(o.keyPair.privateKey),
      })
    }
    await savePreKeys(this._userId, this._prekeys)
    await this._publishPreKeys(fresh.map((o) => ({ keyId: o.keyId, publicKey: exportKey(o.keyPair.publicKey) })))
  }

  private _scheduleReconnect(): void {
    if (this._cancelled) return
    const base  = Math.min(BACKOFF_BASE_MS * Math.pow(2, this._retryCount++), BACKOFF_MAX_MS)
    const delay = base * (0.75 + Math.random() * 0.5)
    this._setConnecting(true)
    this._retryTimer = setTimeout(() => {
      if (!this._cancelled) this._connectWS()
    }, delay)
  }

  private _connectWS(): void {
    const ws = new WebSocket(`${this._wsBase}/v1/relay`)
    this._socket = ws

    ws.addEventListener('open', () => {
      ws.send(JSON.stringify({ type: 'auth', token: this._apiKey }))
      ws.send(JSON.stringify({
        type:     'register',
        userId:   this._userId,
        deviceId: this._deviceId,
      }))
      this._retryCount = 0
      if (!this._cancelled) {
        this._setReady(true)
        this._setConnecting(false)
      }
    })

    ws.addEventListener('message', async (event) => {
      let msg: WireMessage
      try {
        msg = JSON.parse(event.data as string) as WireMessage
      } catch { return }

      if (msg.type !== 'message' || !msg.from || !msg.fromDeviceId || !msg.ciphertext || !msg.nonce || !msg.encHeader) return

      this._emit('wire', {
        direction:  'received',
        ciphertext: msg.ciphertext,
        nonce:      msg.nonce,
        timestamp:  Date.now(),
      })

      try {
        const ratchet = await this._getOrInitReceiverRatchet(msg.from, msg.fromDeviceId, msg.prekey)
        const text    = await ratchet.decrypt({
          encHeader:  importKey(msg.encHeader),
          ciphertext: importKey(msg.ciphertext),
          nonce:      importKey(msg.nonce),
        })
        await saveRatchet(this._userId, `r:${msg.from}:${msg.fromDeviceId}`, ratchet.export())
        // We've heard from this peer device — stop attaching our prekey message.
        this._pendingPrekey.delete(`${msg.from}:${msg.fromDeviceId}`)
        if (!this._cancelled) {
          this._addMessage({ from: msg.from, text, timestamp: Date.now() })
        }
      } catch (err) {
        if (err instanceof DecryptionFailedError) {
          this._emit('error', new DecryptionFailedError(
            `Decryption failed for message from '${msg.from}'.`
          ))
        }
      }
    })

    ws.addEventListener('error', () => {
      if (!this._cancelled) this._emit('error', new Error('WebSocket connection error.'))
    })

    ws.addEventListener('close', () => {
      if (!this._cancelled) {
        this._setReady(false)
        this._emit('disconnected')
        this._scheduleReconnect()
      }
    })
  }

  private async _init(): Promise<void> {
    this._setConnecting(true)
    await sodiumReady()

    // Restore or generate a stable key pair
    const stored = await loadKeyPair(this._userId)
    if (stored) {
      this._keyPair = {
        publicKey:  importKey(stored.pub),
        privateKey: importKey(stored.priv),
      }
    } else {
      const kp = await generateKeyPair()
      this._keyPair = kp
      await saveKeyPair(this._userId, {
        pub:  exportKey(kp.publicKey),
        priv: exportKey(kp.privateKey),
      })
    }

    // Restore or generate a stable device ID for this browser/device
    this._deviceId = await getOrCreateDeviceId(this._userId)

    // Restore message history
    const history = await loadMessages(this._userId)
    if (history.length > 0) this._messages = history

    // Register this device's public key
    const regRes = await fetch(`${this._httpBase}/v1/keys`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this._apiKey}` },
      body:    JSON.stringify({
        userId:    this._userId,
        publicKey: exportKey(this._keyPair.publicKey),
        deviceId:  this._deviceId,
      }),
    })
    if (!regRes.ok) throw new Error(`Key registration failed: ${regRes.status}`)

    // Set up X3DH prekeys (identity key, signed prekey, one-time prekey pool)
    // and publish them so peers can open sessions with us asynchronously.
    await this._initPreKeys()

    if (!this._cancelled) this._connectWS()
  }

  // ── Field encryption (local, no server required) ──────────────────────────

  /**
   * Generate a fresh 32-byte symmetric key for field encryption.
   * Store it securely (env var, secrets manager) — never in the DB.
   */
  async generateFieldKey(): Promise<Uint8Array> {
    return coreGenerateFieldKey()
  }

  /**
   * Encrypt a string value with a 32-byte field key.
   * Returns `{ ciphertext, nonce }` as base64url strings — store both in your DB.
   * Does not require `connect()`.
   */
  async encryptField(value: string, key: Uint8Array): Promise<EncryptedField> {
    return coreEncryptField(value, key)
  }

  /**
   * Decrypt a value produced by `encryptField`.
   * Does not require `connect()`.
   */
  async decryptField(encrypted: EncryptedField, key: Uint8Array): Promise<string> {
    return coreDecryptField(encrypted, key)
  }
}
