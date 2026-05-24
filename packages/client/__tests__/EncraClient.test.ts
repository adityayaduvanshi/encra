import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { EncraClient } from '../src/EncraClient.js'
import * as ratchetStore from '../src/ratchetStore.js'
import { sodiumReady, generateKeyPair, exportKey, DoubleRatchet } from '@encra/core'

// ── WebSocket mock ────────────────────────────────────────────────────────────

type WsListener = (event: { data: string }) => void

class MockWebSocket {
  static OPEN = 1
  readyState   = MockWebSocket.OPEN
  sentMessages: string[] = []

  private openListeners:    (() => void)[]   = []
  private messageListeners: WsListener[]     = []
  private closeListeners:   (() => void)[]   = []
  private errorListeners:   (() => void)[]   = []

  constructor(public url: string) {
    setTimeout(() => this.openListeners.forEach((fn) => fn()), 0)
  }

  send(data: string) { this.sentMessages.push(data) }

  close() {
    this.readyState = 3
    this.closeListeners.forEach((fn) => fn())
  }

  addEventListener(event: string, listener: (e: unknown) => void) {
    if (event === 'open')    this.openListeners.push(listener as () => void)
    else if (event === 'message') this.messageListeners.push(listener as WsListener)
    else if (event === 'close')   this.closeListeners.push(listener as () => void)
    else if (event === 'error')   this.errorListeners.push(listener as () => void)
  }

  simulateMessage(data: string) { this.messageListeners.forEach((fn) => fn({ data })) }
  simulateError()                { this.errorListeners.forEach((fn) => fn()) }
}

// ── fetch mock ────────────────────────────────────────────────────────────────

function makeFetchMock(keyStore: Map<string, string>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()

    if (url.includes('/v1/keys') && init?.method === 'POST') {
      const body = JSON.parse(init.body as string) as { userId: string; publicKey: string }
      keyStore.set(body.userId, body.publicKey)
      return { ok: true, status: 201, json: async () => ({ userId: body.userId }) } as Response
    }

    const match = url.match(/\/v1\/keys\/(.+)$/)
    if (match) {
      const uid = match[1]!
      const key = keyStore.get(uid)
      if (key) return { ok: true, status: 200, json: async () => ({ userId: uid, publicKey: key }) } as Response
      return { ok: false, status: 404, json: async () => ({ error: 'not found' }) } as Response
    }

    return { ok: false, status: 404 } as Response
  })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('EncraClient', () => {
  const keyStore = new Map<string, string>()
  let mockWs: MockWebSocket

  beforeAll(async () => { await sodiumReady() })

  afterEach(() => {
    keyStore.clear()
    vi.restoreAllMocks()
  })

  function setupMocks() {
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    vi.stubGlobal(
      'WebSocket',
      class extends MockWebSocket {
        constructor(url: string) { super(url); mockWs = this }
      }
    )
  }

  it('emits "ready" after key registration and WebSocket connection', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'alice', serverUrl: 'http://localhost:3000' })
    const onReady = vi.fn()
    client.on('ready', onReady)

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    expect(onReady).toHaveBeenCalled()
    expect(client.isReady).toBe(true)
    expect(client.error).toBeNull()
    client.disconnect()
  })

  it('sends a register message when WebSocket opens', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'bob', serverUrl: 'http://localhost:3000' })

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    const reg = mockWs.sentMessages.find((m) => {
      const p = JSON.parse(m) as { type: string; userId?: string }
      return p.type === 'register' && p.userId === 'bob'
    })
    expect(reg).toBeDefined()
    client.disconnect()
  })

  it('emits "error" on WebSocket error, does not set fatal error state', async () => {
    setupMocks()
    const onError = vi.fn()
    const client  = new EncraClient({ apiKey: 'test-key', userId: 'eve', serverUrl: 'http://localhost:3000' })
    client.on('error', onError)

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))
    mockWs.simulateError()
    await new Promise((r) => setTimeout(r, 50))

    expect(onError).toHaveBeenCalledWith(expect.any(Error))
    expect(client.error).toBeNull()
    client.disconnect()
  })

  it('emits "disconnected" and sets isReady false when WebSocket closes', async () => {
    setupMocks()
    const onDisconnected = vi.fn()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'grace', serverUrl: 'http://localhost:3000' })
    client.on('disconnected', onDisconnected)

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))
    mockWs.close()
    await new Promise((r) => setTimeout(r, 50))

    expect(onDisconnected).toHaveBeenCalled()
    expect(client.isReady).toBe(false)
    client.disconnect()
  })

  it('throws when sendMessage is called while disconnected', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'frank', serverUrl: 'http://localhost:3000' })

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))
    mockWs.close()

    await expect(client.sendMessage('bob', 'hi')).rejects.toThrow('Not connected')
    client.disconnect()
  })

  it('throws on fatal init error (key registration fails)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) } as Response)))
    vi.stubGlobal('WebSocket', MockWebSocket)

    const client = new EncraClient({ apiKey: 'bad-key', userId: 'dave', serverUrl: 'http://localhost:3000' })
    await expect(client.connect()).rejects.toThrow('Key registration failed')
  })

  it('fetches sender public key on first incoming message (cache miss)', async () => {
    setupMocks()
    const carolKP = await generateKeyPair()
    keyStore.set('carol', exportKey(carolKP.publicKey))

    const client = new EncraClient({ apiKey: 'test-key', userId: 'alice2', serverUrl: 'http://localhost:3000' })
    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    const wireMsg = JSON.stringify({
      type:       'message',
      from:       'carol',
      ciphertext: exportKey(new Uint8Array(48).fill(0xaa)),
      nonce:      exportKey(new Uint8Array(24).fill(0xbb)),
      header:     { dh: exportKey(carolKP.publicKey), pn: 0, n: 0 },
    })

    mockWs.simulateMessage(wireMsg)
    await new Promise((r) => setTimeout(r, 200))

    const fetchMock = vi.mocked(globalThis.fetch as ReturnType<typeof vi.fn>)
    const keyFetch  = fetchMock.mock.calls.find(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/v1/keys/carol')
    )
    expect(keyFetch).toBeDefined()
    expect(client.messages).toHaveLength(0) // decryption fails — wrong bytes
    expect(client.isReady).toBe(true)
    client.disconnect()
  })

  it('ignores messages with unknown type or missing fields', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'henry', serverUrl: 'http://localhost:3000' })
    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    mockWs.simulateMessage('not-json{{{')
    mockWs.simulateMessage(JSON.stringify({ type: 'ping' }))
    mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'x' }))
    mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'x', ciphertext: 'a', nonce: 'b' }))
    await new Promise((r) => setTimeout(r, 100))

    expect(client.messages).toHaveLength(0)
    client.disconnect()
  })

  it('emits "wire" with direction "received" on incoming message', async () => {
    setupMocks()
    const peerKP = await generateKeyPair()
    keyStore.set('ivy', exportKey(peerKP.publicKey))

    const onWire = vi.fn()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'jack', serverUrl: 'http://localhost:3000' })
    client.on('wire', onWire)

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    mockWs.simulateMessage(JSON.stringify({
      type: 'message', from: 'ivy',
      ciphertext: exportKey(new Uint8Array(48).fill(0xcc)),
      nonce:      exportKey(new Uint8Array(24).fill(0xdd)),
      header:     { dh: exportKey(peerKP.publicKey), pn: 0, n: 0 },
    }))
    await new Promise((r) => setTimeout(r, 200))

    expect(onWire).toHaveBeenCalledWith(expect.objectContaining({ direction: 'received' }))
    client.disconnect()
  })

  it('sendMessage encrypts, sends via WebSocket, and emits wire + message events', async () => {
    setupMocks()
    const peerKP = await generateKeyPair()
    keyStore.set('mallory', exportKey(peerKP.publicKey))

    const fakeRatchet = {
      encrypt: vi.fn().mockResolvedValue({
        header:     { dh: exportKey(peerKP.publicKey), pn: 0, n: 0 },
        ciphertext: new Uint8Array(48).fill(0x01),
        nonce:      new Uint8Array(24).fill(0x02),
      }),
      export: vi.fn().mockReturnValue({ version: 1 }),
    }
    vi.spyOn(DoubleRatchet, 'initSender').mockResolvedValue(
      fakeRatchet as unknown as InstanceType<typeof DoubleRatchet>
    )

    const onWire    = vi.fn()
    const onMessage = vi.fn()
    const client    = new EncraClient({ apiKey: 'test-key', userId: 'nina', serverUrl: 'http://localhost:3000' })
    client.on('wire',    onWire)
    client.on('message', onMessage)

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))
    await client.sendMessage('mallory', 'hello')

    const frame = mockWs.sentMessages.find((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'message' && p.to === 'mallory'
    })
    expect(frame).toBeDefined()
    expect(onWire).toHaveBeenCalledWith(expect.objectContaining({ direction: 'sent' }))
    expect(onMessage).toHaveBeenCalledWith(expect.objectContaining({ from: 'nina', text: 'hello' }))
    expect(client.messages).toHaveLength(1)
    client.disconnect()
  })

  it('restores key pair from IndexedDB without generating a new one', async () => {
    setupMocks()
    const storedKP = await generateKeyPair()
    vi.spyOn(ratchetStore, 'loadKeyPair').mockResolvedValue({
      pub:  exportKey(storedKP.publicKey),
      priv: exportKey(storedKP.privateKey),
    })
    const saveKeyPairSpy = vi.spyOn(ratchetStore, 'saveKeyPair').mockResolvedValue()

    const client = new EncraClient({ apiKey: 'test-key', userId: 'leo', serverUrl: 'http://localhost:3000' })
    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    expect(saveKeyPairSpy).not.toHaveBeenCalled()
    client.disconnect()
  })

  it('off() removes a listener', async () => {
    setupMocks()
    const client  = new EncraClient({ apiKey: 'test-key', userId: 'mia', serverUrl: 'http://localhost:3000' })
    const onReady = vi.fn()
    client.on('ready', onReady)
    client.off('ready', onReady)

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    expect(onReady).not.toHaveBeenCalled()
    client.disconnect()
  })
})
