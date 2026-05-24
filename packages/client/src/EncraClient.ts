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

// ── Public types ──────────────────────────────────────────────────────────────

export interface Message {
  from:      string
  text:      string
  timestamp: number
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
  /** WebSocket is open and the client is registered. */
  ready:        []
  /** Connecting for the first time or after a disconnect. */
  connecting:   []
  /** WebSocket closed; automatic reconnect is scheduled. */
  disconnected: []
  /** A new decrypted message arrived. */
  message:      [msg: Message]
  /**
   * A recoverable error occurred (decryption failure, WS error).
   * Fatal init errors are thrown by `connect()` instead.
   */
  error:        [err: Error]
  /** Raw wire data for every encrypted send/receive. Useful for debugging. */
  wire:         [event: WireEvent]
}

type Listener<K extends keyof EventMap> = (...args: EventMap[K]) => void

// ── Internal wire shape ───────────────────────────────────────────────────────

interface WireMessage {
  type:       string
  from?:      string
  ciphertext?: string
  nonce?:     string
  header?:    MessageHeader
}

const BACKOFF_BASE_MS = 1_000
const BACKOFF_MAX_MS  = 60_000
const MAX_MESSAGES    = 200
const ENCRA_SERVER_URL = 'https://api.encra.dev'

// ── EncraClient ───────────────────────────────────────────────────────────────

/**
 * Framework-agnostic Encra client.
 *
 * Generates (or restores from IndexedDB) a key pair on `connect()`, registers
 * it with the server, and opens a WebSocket relay. All Double Ratchet
 * encryption/decryption is handled internally. State is persisted to IndexedDB
 * so conversations survive page reloads. The WebSocket reconnects automatically
 * with exponential backoff.
 *
 * Works in any JS environment — React, Vue, Svelte, Angular, vanilla JS,
 * Node.js. For React, prefer the `useE2EChat` hook from `@encra/react` which
 * wraps this client.
 *
 * @example
 * const client = new EncraClient({ apiKey: 'e2e_live_xxx', userId: 'alice' })
 *
 * client.on('message', (msg) => console.log(msg.from, msg.text))
 * client.on('ready',   ()    => console.log('connected'))
 *
 * await client.connect()
 * await client.sendMessage('bob', 'hello!')
 *
 * // Later:
 * client.disconnect()
 */
export class EncraClient {
  // ── State ─────────────────────────────────────────────────────────────────

  private _messages:    Message[]   = []
  private _isReady:     boolean     = false
  private _isConnecting:boolean     = false
  private _error:       Error|null  = null

  private _keyPair:     KeyPair | null               = null
  private _ratchets:    Map<string, DoubleRatchet>   = new Map()
  private _socket:      WebSocket | null             = null
  private _retryCount:  number                       = 0
  private _retryTimer:  ReturnType<typeof setTimeout>|null = null
  private _cancelled:   boolean                      = false
  private _connected:   boolean                      = false

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

  get isReady():      boolean   { return this._isReady }
  get isConnecting(): boolean   { return this._isConnecting }
  get error():        Error|null{ return this._error }
  /** Snapshot of all messages (sent + received), newest last. */
  get messages():     Message[] { return this._messages }

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

  /**
   * Initialise crypto, register the public key, and open the WebSocket.
   * Resolves when the WebSocket is open and the client is registered.
   * Throws on fatal errors (e.g. key registration fails).
   * After the first connection, automatic reconnect is managed internally.
   */
  async connect(): Promise<void> {
    if (this._connected) return
    this._connected = true
    await this._init()
  }

  /**
   * Close the connection and cancel any pending reconnects.
   * After calling this the instance should not be reused.
   */
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
   * Encrypt `text` and send it to `to`.
   * Throws if the WebSocket is not currently open.
   *
   * @param to   - Recipient's userId.
   * @param text - Plaintext message.
   */
  async sendMessage(to: string, text: string): Promise<void> {
    if (!this._socket || this._socket.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected. Wait for the "ready" event before sending.')
    }

    const ratchet = await this._getOrInitSenderRatchet(to)
    const { header, ciphertext, nonce } = await ratchet.encrypt(text)
    await saveRatchet(this._userId, `s:${to}`, ratchet.export())

    const ctB64 = exportKey(ciphertext)
    const nB64  = exportKey(nonce)

    this._socket.send(JSON.stringify({
      type: 'message', to, ciphertext: ctB64, nonce: nB64, header,
    }))

    this._emit('wire', { direction: 'sent', ciphertext: ctB64, nonce: nB64, timestamp: Date.now() })

    this._addMessage({ from: this._userId, text, timestamp: Date.now() })
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private _setReady(v: boolean)      { this._isReady      = v; if (v) this._emit('ready') }
  private _setConnecting(v: boolean) { this._isConnecting = v; if (v) this._emit('connecting') }

  private _addMessage(msg: Message): void {
    const next = [...this._messages, msg]
    this._messages = next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next
    void saveMessages(this._userId, this._messages)
    this._emit('message', msg)
  }

  private async _fetchPeerPublicKey(peerId: string): Promise<Uint8Array> {
    const res = await fetch(`${this._httpBase}/v1/keys/${peerId}`, {
      headers: { Authorization: `Bearer ${this._apiKey}` },
    })
    if (!res.ok) {
      throw new Error(
        `Could not fetch public key for '${peerId}': ${res.status}. ` +
        `Make sure ${peerId} has registered.`
      )
    }
    const { publicKey: pubB64 } = (await res.json()) as { publicKey: string }
    return importKey(pubB64)
  }

  private async _getOrInitSenderRatchet(peerId: string): Promise<DoubleRatchet> {
    const key      = `s:${peerId}`
    const existing = this._ratchets.get(key)
    if (existing) return existing

    const stored = await loadRatchet(this._userId, key)
    if (stored) {
      const ratchet = await DoubleRatchet.fromExport(stored)
      this._ratchets.set(key, ratchet)
      return ratchet
    }

    if (!this._keyPair) throw new Error('Key pair not initialised.')
    const peerPub = await this._fetchPeerPublicKey(peerId)
    const shared  = await deriveSharedSecret(this._keyPair.privateKey, peerPub)
    const ratchet = await DoubleRatchet.initSender(shared, peerPub)
    this._ratchets.set(key, ratchet)
    await saveRatchet(this._userId, key, ratchet.export())
    return ratchet
  }

  private async _getOrInitReceiverRatchet(peerId: string): Promise<DoubleRatchet> {
    const key      = `r:${peerId}`
    const existing = this._ratchets.get(key)
    if (existing) return existing

    const stored = await loadRatchet(this._userId, key)
    if (stored) {
      const ratchet = await DoubleRatchet.fromExport(stored)
      this._ratchets.set(key, ratchet)
      return ratchet
    }

    if (!this._keyPair) throw new Error('Key pair not initialised.')
    const peerPub = await this._fetchPeerPublicKey(peerId)
    const shared  = await deriveSharedSecret(this._keyPair.privateKey, peerPub)
    const ratchet = await DoubleRatchet.initReceiver(shared, this._keyPair)
    this._ratchets.set(key, ratchet)
    await saveRatchet(this._userId, key, ratchet.export())
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
      ws.send(JSON.stringify({ type: 'register', userId: this._userId }))
      this._retryCount = 0
      if (!this._cancelled) this._setReady(true), this._setConnecting(false)
    })

    ws.addEventListener('message', async (event) => {
      let msg: WireMessage
      try {
        msg = JSON.parse(event.data as string) as WireMessage
      } catch { return }

      if (msg.type !== 'message' || !msg.from || !msg.ciphertext || !msg.nonce || !msg.header) return

      this._emit('wire', {
        direction:  'received',
        ciphertext: msg.ciphertext,
        nonce:      msg.nonce,
        timestamp:  Date.now(),
      })

      try {
        const ratchet = await this._getOrInitReceiverRatchet(msg.from)
        const text = await ratchet.decrypt({
          header:     msg.header,
          ciphertext: importKey(msg.ciphertext),
          nonce:      importKey(msg.nonce),
        })
        await saveRatchet(this._userId, `r:${msg.from}`, ratchet.export())
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

    // Restore message history
    const history = await loadMessages(this._userId)
    if (history.length > 0) this._messages = history

    // Register public key (idempotent upsert)
    const regRes = await fetch(`${this._httpBase}/v1/keys`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this._apiKey}` },
      body:    JSON.stringify({ userId: this._userId, publicKey: exportKey(this._keyPair.publicKey) }),
    })
    if (!regRes.ok) throw new Error(`Key registration failed: ${regRes.status}`)

    if (!this._cancelled) this._connectWS()
  }
}
