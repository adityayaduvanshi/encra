import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { EncraClient, MAX_FILE_BYTES } from '../src/EncraClient.js'
import type { EncryptedFile, EncryptedFields } from '../src/EncraClient.js'
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
    if (event === 'open')         this.openListeners.push(listener as () => void)
    else if (event === 'message') this.messageListeners.push(listener as WsListener)
    else if (event === 'close')   this.closeListeners.push(listener as () => void)
    else if (event === 'error')   this.errorListeners.push(listener as () => void)
  }

  simulateMessage(data: string) { this.messageListeners.forEach((fn) => fn({ data })) }
  simulateError()                { this.errorListeners.forEach((fn) => fn()) }
}

// ── fetch mock ────────────────────────────────────────────────────────────────

const TEST_DEVICE_ID = 'test-device'

/**
 * Returns a fetch mock that speaks the multi-device key-server protocol:
 *   POST /v1/keys     → { userId, deviceId }
 *   GET  /v1/keys/:id → { userId, devices: [{ deviceId, publicKey }] }
 */
function makeFetchMock(keyStore: Map<string, string>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()

    if (url.includes('/v1/keys') && init?.method === 'POST') {
      const body = JSON.parse(init.body as string) as {
        userId: string; publicKey: string; deviceId?: string
      }
      keyStore.set(body.userId, body.publicKey)
      return {
        ok: true, status: 201,
        json: async () => ({ userId: body.userId, deviceId: body.deviceId ?? TEST_DEVICE_ID }),
      } as Response
    }

    const match = url.match(/\/v1\/keys\/(.+)$/)
    if (match) {
      const uid = match[1]!
      const key = keyStore.get(uid)
      if (key) {
        return {
          ok: true, status: 200,
          json: async () => ({
            userId: uid,
            devices: [{ deviceId: TEST_DEVICE_ID, publicKey: key }],
          }),
        } as Response
      }
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
    vi.spyOn(ratchetStore, 'getOrCreateDeviceId').mockResolvedValue(TEST_DEVICE_ID)
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

  it('sends a register message with userId and deviceId when WebSocket opens', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'bob', serverUrl: 'http://localhost:3000' })

    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    const reg = mockWs.sentMessages.find((m) => {
      const p = JSON.parse(m) as { type: string; userId?: string }
      return p.type === 'register' && p.userId === 'bob'
    })
    expect(reg).toBeDefined()

    // deviceId must be included for relay routing
    const parsed = JSON.parse(reg!) as { type: string; userId: string; deviceId: string }
    expect(parsed.deviceId).toBe(TEST_DEVICE_ID)
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
    vi.spyOn(ratchetStore, 'getOrCreateDeviceId').mockResolvedValue(TEST_DEVICE_ID)

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

    // fromDeviceId is required for per-device ratchet keying
    const wireMsg = JSON.stringify({
      type:         'message',
      from:         'carol',
      fromDeviceId: TEST_DEVICE_ID,
      ciphertext:   exportKey(new Uint8Array(48).fill(0xaa)),
      nonce:        exportKey(new Uint8Array(24).fill(0xbb)),
      header:       { dh: exportKey(carolKP.publicKey), pn: 0, n: 0 },
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
    // Missing fromDeviceId, ciphertext, nonce, or header — all ignored
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

    // fromDeviceId required; "wire" event fires before decryption attempt
    mockWs.simulateMessage(JSON.stringify({
      type:         'message',
      from:         'ivy',
      fromDeviceId: TEST_DEVICE_ID,
      ciphertext:   exportKey(new Uint8Array(48).fill(0xcc)),
      nonce:        exportKey(new Uint8Array(24).fill(0xdd)),
      header:       { dh: exportKey(peerKP.publicKey), pn: 0, n: 0 },
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

    // mallory has 1 device → 1 wire frame
    const frame = mockWs.sentMessages.find((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'message' && p.to === 'mallory'
    })
    expect(frame).toBeDefined()

    // Frame must include toDeviceId for relay routing
    const parsedFrame = JSON.parse(frame!) as { toDeviceId?: string }
    expect(parsedFrame.toDeviceId).toBe(TEST_DEVICE_ID)

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

  // ── encryptFile / decryptFile ─────────────────────────────────────────────

  async function makeConnectedPair(
    aliceId: string,
    bobId:   string,
  ): Promise<[EncraClient, EncraClient, () => void]> {
    setupMocks()
    const aliceKP = await generateKeyPair()
    const bobKP   = await generateKeyPair()

    // Pre-populate keyStore so each client can fetch the other's key
    keyStore.set(aliceId, exportKey(aliceKP.publicKey))
    keyStore.set(bobId,   exportKey(bobKP.publicKey))

    // Stub IDB so each client loads the pre-generated key pair
    vi.spyOn(ratchetStore, 'loadKeyPair').mockImplementation(async (uid) => {
      if (uid === aliceId) return { pub: exportKey(aliceKP.publicKey), priv: exportKey(aliceKP.privateKey) }
      if (uid === bobId)   return { pub: exportKey(bobKP.publicKey),   priv: exportKey(bobKP.privateKey) }
      return null
    })
    vi.spyOn(ratchetStore, 'saveKeyPair').mockResolvedValue()

    const alice = new EncraClient({ apiKey: 'test-key', userId: aliceId, serverUrl: 'http://localhost:3000' })
    const bob   = new EncraClient({ apiKey: 'test-key', userId: bobId,   serverUrl: 'http://localhost:3000' })

    await alice.connect()
    await new Promise((r) => setTimeout(r, 100))
    await bob.connect()
    await new Promise((r) => setTimeout(r, 100))

    return [alice, bob, () => { alice.disconnect(); bob.disconnect() }]
  }

  it('encryptFile → decryptFile round-trips a text file', async () => {
    const [alice, bob, cleanup] = await makeConnectedPair('ef-alice', 'ef-bob')

    const file = new File(['Hello from EncraClient!'], 'hello.txt', { type: 'text/plain' })
    const enc  = await alice.encryptFile(file, 'ef-bob')

    // Top-level metadata is plaintext
    expect(enc.name).toBe('hello.txt')
    expect(enc.mimeType).toBe('text/plain')
    expect(enc.size).toBe(file.size)

    // Encrypted payload is inside the devices array
    expect(enc.devices).toHaveLength(1)
    expect(enc.devices[0]!.deviceId).toBe(TEST_DEVICE_ID)
    expect(enc.devices[0]!.ciphertext).toBeInstanceOf(Uint8Array)
    expect(enc.devices[0]!.nonce).toBeInstanceOf(Uint8Array)

    const decrypted = await bob.decryptFile(enc, 'ef-alice')
    const text = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader()
      reader.onload  = () => resolve(reader.result as string)
      reader.onerror = () => reject(reader.error)
      reader.readAsText(decrypted)
    })
    expect(text).toBe('Hello from EncraClient!')
    expect(decrypted.name).toBe('hello.txt')
    expect(decrypted.type).toBe('text/plain')

    cleanup()
  })

  it('encryptFile uses default name "file" for a plain Blob', async () => {
    const [alice, , cleanup] = await makeConnectedPair('ef-blob-alice', 'ef-blob-bob')

    const blob = new Blob(['data'], { type: 'application/octet-stream' })
    const enc  = await alice.encryptFile(blob, 'ef-blob-bob')

    expect(enc.name).toBe('file')
    expect(enc.mimeType).toBe('application/octet-stream')
    expect(enc.devices).toHaveLength(1)
    cleanup()
  })

  it('encryptFile throws if file exceeds MAX_FILE_BYTES', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'ef-big', serverUrl: 'http://localhost:3000' })
    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    const bigFile = { size: MAX_FILE_BYTES + 1, type: 'text/plain', arrayBuffer: vi.fn() } as unknown as File
    await expect(client.encryptFile(bigFile, 'anyone')).rejects.toThrow('too large')
    client.disconnect()
  })

  it('encryptFile throws when recipient key is not found (404)', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'ef-404', serverUrl: 'http://localhost:3000' })
    await client.connect()
    await new Promise((r) => setTimeout(r, 100))

    const file = new File(['data'], 'f.txt')
    await expect(client.encryptFile(file, 'ghost')).rejects.toThrow(
      "Could not fetch public keys for 'ghost'"
    )
    client.disconnect()
  })

  it('decryptFile throws on tampered ciphertext', async () => {
    const [alice, bob, cleanup] = await makeConnectedPair('ef-tamper-alice', 'ef-tamper-bob')

    const file = new File(['secret'], 'secret.txt', { type: 'text/plain' })
    const enc  = await alice.encryptFile(file, 'ef-tamper-bob')

    // Tamper with the ciphertext for this device's envelope
    const tampered: EncryptedFile = {
      name:     enc.name,
      mimeType: enc.mimeType,
      size:     enc.size,
      devices:  [{
        deviceId:   enc.devices[0]!.deviceId,
        ciphertext: new Uint8Array(enc.devices[0]!.ciphertext.length).fill(0xff),
        nonce:      enc.devices[0]!.nonce,
      }],
    }
    await expect(bob.decryptFile(tampered, 'ef-tamper-alice')).rejects.toThrow()

    cleanup()
  })

  it('encryptFile caches peer public key (only fetches once)', async () => {
    const [alice, , cleanup] = await makeConnectedPair('ef-cache-alice', 'ef-cache-bob')

    const fetchMock = vi.mocked(globalThis.fetch as ReturnType<typeof vi.fn>)
    const file = new File(['a'], 'a.txt')
    await alice.encryptFile(file, 'ef-cache-bob')
    await alice.encryptFile(file, 'ef-cache-bob')

    const keyFetches = fetchMock.mock.calls.filter(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/v1/keys/ef-cache-bob')
    )
    expect(keyFetches.length).toBe(1)
    cleanup()
  })

  it('throws when encryptFile called before connect()', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'ef-nc', serverUrl: 'http://localhost:3000' })
    const file = new File(['x'], 'x.txt')
    await expect(client.encryptFile(file, 'other')).rejects.toThrow('not connected')
  })

  // ── encryptFields / decryptFields ─────────────────────────────────────────

  it('encryptFields → decryptFields round-trips all field values', async () => {
    const [alice, bob, cleanup] = await makeConnectedPair('ef2-alice', 'ef2-bob')

    const fields  = { name: 'Alice Smith', ssn: '123-45-6789', notes: 'Private notes 🔐' }
    const enc     = await alice.encryptFields(fields, 'ef2-bob')

    // EncryptedFields has a devices array (one per recipient device)
    expect(enc.devices).toHaveLength(1)
    expect(enc.devices[0]!.deviceId).toBe(TEST_DEVICE_ID)

    const devFields = enc.devices[0]!.fields
    expect(Object.keys(devFields).sort()).toEqual(['name', 'notes', 'ssn'])
    for (const key of Object.keys(fields) as (keyof typeof fields)[]) {
      expect(devFields[key]).toHaveProperty('ciphertext')
      expect(devFields[key]).toHaveProperty('nonce')
      expect(devFields[key]!.ciphertext).not.toContain(fields[key])
    }

    // Each field gets a unique nonce
    const nonces = Object.values(devFields).map((v) => v.nonce)
    expect(new Set(nonces).size).toBe(nonces.length)

    const decrypted = await bob.decryptFields(enc, 'ef2-alice')
    expect(decrypted).toEqual(fields)

    cleanup()
  })

  it('encryptFields handles empty object', async () => {
    const [alice, , cleanup] = await makeConnectedPair('ef2-empty-alice', 'ef2-empty-bob')

    const enc = await alice.encryptFields({}, 'ef2-empty-bob')
    expect(enc.devices).toHaveLength(1)
    expect(enc.devices[0]!.fields).toEqual({})
    cleanup()
  })

  it('encryptFields produces unique ciphertexts on repeated calls (fresh nonce)', async () => {
    const [alice, , cleanup] = await makeConnectedPair('ef2-nonce-alice', 'ef2-nonce-bob')

    const enc1 = await alice.encryptFields({ secret: 'same' }, 'ef2-nonce-bob')
    const enc2 = await alice.encryptFields({ secret: 'same' }, 'ef2-nonce-bob')

    expect(enc1.devices[0]!.fields.secret!.ciphertext).not.toBe(enc2.devices[0]!.fields.secret!.ciphertext)
    expect(enc1.devices[0]!.fields.secret!.nonce).not.toBe(enc2.devices[0]!.fields.secret!.nonce)
    cleanup()
  })

  it('decryptFields throws on tampered ciphertext', async () => {
    const [alice, bob, cleanup] = await makeConnectedPair('ef2-tamper-a', 'ef2-tamper-b')

    const enc = await alice.encryptFields({ x: 'value' }, 'ef2-tamper-b')

    const tampered: EncryptedFields = {
      devices: [{
        deviceId: enc.devices[0]!.deviceId,
        fields: {
          ...enc.devices[0]!.fields,
          x: {
            ...enc.devices[0]!.fields.x!,
            ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        },
      }],
    }
    await expect(bob.decryptFields(tampered, 'ef2-tamper-a')).rejects.toThrow()
    cleanup()
  })

  it('encryptFields throws if a field value is not a string', async () => {
    const [alice, , cleanup] = await makeConnectedPair('ef2-type-alice', 'ef2-type-bob')

    await expect(
      // @ts-expect-error — intentional runtime type check
      alice.encryptFields({ age: 42 }, 'ef2-type-bob')
    ).rejects.toThrow('must be a string')
    cleanup()
  })

  it('throws when encryptFields called before connect()', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'test-key', userId: 'ef2-nc', serverUrl: 'http://localhost:3000' })
    await expect(client.encryptFields({ x: 'y' }, 'other')).rejects.toThrow('not connected')
  })
})
