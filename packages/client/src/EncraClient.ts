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
  getOrCreateDeviceId,
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

interface WireMessage {
  type:          string
  from?:         string
  fromDeviceId?: string
  ciphertext?:   string
  nonce?:        string
  header?:       MessageHeader
}

const BACKOFF_BASE_MS  = 1_000
const BACKOFF_MAX_MS   = 60_000
const MAX_MESSAGES     = 200
const ENCRA_SERVER_URL = 'https://api.encra.dev'

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

  private _keyPair:      KeyPair | null                = null
  private _deviceId:     string | null                 = null
  private _ratchets:     Map<string, DoubleRatchet>    = new Map()
  private _peerKeyCache: Map<string, DeviceKey[]>      = new Map()
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
    this._ratchets.clear()
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
      const ratchet     = await this._getOrInitSenderRatchet(to, device)
      const { header, ciphertext, nonce } = await ratchet.encrypt(text)
      await saveRatchet(this._userId, `s:${to}:${device.deviceId}`, ratchet.export())

      const ctB64 = exportKey(ciphertext)
      const nB64  = exportKey(nonce)

      this._socket.send(JSON.stringify({
        type: 'message', to, toDeviceId: device.deviceId,
        ciphertext: ctB64, nonce: nB64, header,
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

    const peerDevices = await this._fetchPeerDeviceKeys(from)
    const senderDevice = peerDevices.find((d) => d.publicKey) ?? peerDevices[0]
    if (!senderDevice) {
      throw new DecryptionFailedError(`decryptFile: could not fetch sender key for '${from}'.`)
    }

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

  /** Fetch all device keys for a peer, with in-memory caching. */
  private async _fetchPeerDeviceKeys(peerId: string): Promise<DeviceKey[]> {
    const cached = this._peerKeyCache.get(peerId)
    if (cached) return cached

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
    return keys
  }

  private async _getOrInitSenderRatchet(peerId: string, device: DeviceKey): Promise<DoubleRatchet> {
    const ratchetKey = `s:${peerId}:${device.deviceId}`
    const existing   = this._ratchets.get(ratchetKey)
    if (existing) return existing

    const stored = await loadRatchet(this._userId, ratchetKey)
    if (stored) {
      const ratchet = await DoubleRatchet.fromExport(stored)
      this._ratchets.set(ratchetKey, ratchet)
      return ratchet
    }

    if (!this._keyPair) throw new Error('Key pair not initialised.')
    const shared  = await deriveSharedSecret(this._keyPair.privateKey, device.publicKey)
    const ratchet = await DoubleRatchet.initSender(shared, device.publicKey)
    this._ratchets.set(ratchetKey, ratchet)
    await saveRatchet(this._userId, ratchetKey, ratchet.export())
    return ratchet
  }

  private async _getOrInitReceiverRatchet(
    peerId:       string,
    fromDeviceId: string,
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

    if (!this._keyPair) throw new Error('Key pair not initialised.')
    // Find the sender's specific device key
    const peerDevices  = await this._fetchPeerDeviceKeys(peerId)
    const senderDevice = peerDevices.find((d) => d.deviceId === fromDeviceId) ?? peerDevices[0]
    if (!senderDevice) throw new Error(`Key not found for device ${fromDeviceId} of '${peerId}'.`)

    const shared  = await deriveSharedSecret(this._keyPair.privateKey, senderDevice.publicKey)
    const ratchet = await DoubleRatchet.initReceiver(shared, this._keyPair)
    this._ratchets.set(ratchetKey, ratchet)
    await saveRatchet(this._userId, ratchetKey, ratchet.export())
    return ratchet
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
    const ws = new WebSocket(`${this._wsBase}/v1/relay?token=${encodeURIComponent(this._apiKey)}`)
    this._socket = ws

    ws.addEventListener('open', () => {
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

      if (msg.type !== 'message' || !msg.from || !msg.fromDeviceId || !msg.ciphertext || !msg.nonce || !msg.header) return

      this._emit('wire', {
        direction:  'received',
        ciphertext: msg.ciphertext,
        nonce:      msg.nonce,
        timestamp:  Date.now(),
      })

      try {
        const ratchet = await this._getOrInitReceiverRatchet(msg.from, msg.fromDeviceId)
        const text    = await ratchet.decrypt({
          header:     msg.header,
          ciphertext: importKey(msg.ciphertext),
          nonce:      importKey(msg.nonce),
        })
        await saveRatchet(this._userId, `r:${msg.from}:${msg.fromDeviceId}`, ratchet.export())
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

    if (!this._cancelled) this._connectWS()
  }
}
