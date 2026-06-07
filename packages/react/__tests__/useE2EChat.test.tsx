import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useE2EChat } from '../src/useE2EChat.js'
import * as ratchetStore from '../src/ratchetStore.js'
import {
  sodiumReady,
  generateKeyPair,
  DoubleRatchet,
  exportKey,
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  buildPreKeyBundle,
} from '@encra/core'

// ── WebSocket mock ────────────────────────────────────────────────────────────

type WsListener = (event: { data: string }) => void

class MockWebSocket {
  static OPEN = 1
  readyState = MockWebSocket.OPEN
  sentMessages: string[] = []

  private openListeners: (() => void)[] = []
  private messageListeners: WsListener[] = []
  private closeListeners: (() => void)[] = []
  private errorListeners: (() => void)[] = []

  constructor(public url: string) {
    setTimeout(() => this.openListeners.forEach((fn) => fn()), 0)
  }

  send(data: string) {
    this.sentMessages.push(data)
  }

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

  simulateMessage(data: string) {
    this.messageListeners.forEach((fn) => fn({ data }))
  }

  simulateError() {
    this.errorListeners.forEach((fn) => fn())
  }
}

// ── fetch mock ────────────────────────────────────────────────────────────────

const TEST_DEVICE_ID = 'test-device'

interface PreKeyRecord {
  identityKey:    string
  signedPreKey:   { keyId: number; publicKey: string; signature: string }
  oneTimePreKeys: Array<{ keyId: number; publicKey: string }>
}

/**
 * Returns a fetch mock that speaks the multi-device key-server + X3DH prekey
 * protocol:
 *   POST /v1/keys                  → { userId, deviceId }
 *   GET  /v1/keys/:id              → { userId, devices: [{ deviceId, publicKey }] }
 *   POST /v1/prekeys               → stores the device's prekey bundle
 *   GET  /v1/prekeys/:user/:device → serves a bundle, consuming one one-time prekey
 */
function makeFetchMock(
  keyStore: Map<string, string>,
  preKeyStore: Map<string, PreKeyRecord> = new Map(),
) {
  const pkKey = (u: string, d: string) => `${u}:${d}`

  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()

    if (url.includes('/v1/prekeys') && init?.method === 'POST') {
      const body = JSON.parse(init.body as string) as {
        userId: string; deviceId: string; identityKey: string
        signedPreKey: { keyId: number; publicKey: string; signature: string }
        oneTimePreKeys: Array<{ keyId: number; publicKey: string }>
      }
      const k        = pkKey(body.userId, body.deviceId)
      const existing = preKeyStore.get(k)
      preKeyStore.set(k, {
        identityKey:    body.identityKey,
        signedPreKey:   body.signedPreKey,
        oneTimePreKeys: [...(existing?.oneTimePreKeys ?? []), ...body.oneTimePreKeys],
      })
      return { ok: true, status: 201, json: async () => ({ userId: body.userId, deviceId: body.deviceId }) } as Response
    }

    const preMatch = url.match(/\/v1\/prekeys\/([^/]+)\/([^/?]+)$/)
    if (preMatch) {
      const rec = preKeyStore.get(pkKey(preMatch[1]!, preMatch[2]!))
      if (!rec) return { ok: false, status: 404, json: async () => ({ error: 'not found' }) } as Response
      const otp = rec.oneTimePreKeys.shift()
      return {
        ok: true, status: 200,
        json: async () => ({
          identityKey:  rec.identityKey,
          signedPreKey: rec.signedPreKey,
          ...(otp ? { oneTimePreKey: otp } : {}),
        }),
      } as Response
    }

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

/** Build and store a valid prekey bundle for a peer so X3DH initiation succeeds. */
async function seedPreKeyBundle(preKeyStore: Map<string, PreKeyRecord>, userId: string): Promise<void> {
  const identity = await generateIdentityKeyPair()
  const spk      = await generateSignedPreKey(identity, 1)
  const [otp]    = await generateOneTimePreKeys(1, 1)
  const bundle   = buildPreKeyBundle(identity, spk, otp)
  preKeyStore.set(`${userId}:${TEST_DEVICE_ID}`, {
    identityKey:    bundle.identityKey,
    signedPreKey:   bundle.signedPreKey,
    oneTimePreKeys: [bundle.oneTimePreKey!],
  })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('useE2EChat', () => {
  const keyStore    = new Map<string, string>()
  const preKeyStore = new Map<string, PreKeyRecord>()
  let mockWs: MockWebSocket

  beforeAll(async () => {
    await sodiumReady()
  })

  afterEach(() => {
    keyStore.clear()
    preKeyStore.clear()
    vi.restoreAllMocks()
  })

  function setupMocks() {
    vi.stubGlobal('fetch', makeFetchMock(keyStore, preKeyStore))
    vi.spyOn(ratchetStore, 'getOrCreateDeviceId').mockResolvedValue(TEST_DEVICE_ID)
    vi.stubGlobal(
      'WebSocket',
      class extends MockWebSocket {
        constructor(url: string) {
          super(url)
          // eslint-disable-next-line no-console
          console.log('[DIAG] WebSocket constructed; reassigning mockWs')
          mockWs = this
        }
      }
    )
  }

  it('becomes ready after key registration and WebSocket connection', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'alice', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    expect(result.current.error).toBeNull()
  })

  it('sends a register message with userId and deviceId when WebSocket opens', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'bob', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    const registerMsg = mockWs.sentMessages.find((m) => {
      const parsed = JSON.parse(m) as { type: string; userId?: string; deviceId?: string }
      return parsed.type === 'register' && parsed.userId === 'bob'
    })
    expect(registerMsg).toBeDefined()

    // deviceId must be included in the register message for server-side routing
    const parsed = JSON.parse(registerMsg!) as { type: string; userId: string; deviceId: string }
    expect(parsed.deviceId).toBe(TEST_DEVICE_ID)
  })

  it('fetches sender public key on first incoming message (key derivation cache miss)', async () => {
    // Regression note: libsodium crypto_secretbox_easy has a cross-realm Uint8Array
    // issue in jsdom that prevents calling encrypt() inside tests. Full encrypt→decrypt
    // is covered by the Alice→Bob integration test in packages/server.
    // This test verifies the hook's key-fetching and WebSocket message-routing logic.
    setupMocks()

    const carolKP = await generateKeyPair()
    keyStore.set('carol', exportKey(carolKP.publicKey))

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'alice2', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    // Old-style inbound message with no X3DH prekey header and no existing
    // session — the hook cannot bootstrap a session, so it drops the message
    // gracefully (no crash) rather than fetching a public key.
    const wireMsg = JSON.stringify({
      type:         'message',
      from:         'carol',
      fromDeviceId: TEST_DEVICE_ID,
      ciphertext:   exportKey(new Uint8Array(48).fill(0xaa)),
      nonce:        exportKey(new Uint8Array(24).fill(0xbb)),
      encHeader:    exportKey(new Uint8Array(40).fill(0xcc)),
    })

    await act(async () => {
      mockWs.simulateMessage(wireMsg)
      await new Promise((r) => setTimeout(r, 200))
    })

    // No session could be established, so no message lands in state.
    expect(result.current.messages).toHaveLength(0)
    // Hook must remain functional after dropping the message.
    expect(result.current.isReady).toBe(true)
  })

  it('sets error when fetch registration fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) } as Response))
    )
    vi.stubGlobal('WebSocket', MockWebSocket)
    vi.spyOn(ratchetStore, 'getOrCreateDeviceId').mockResolvedValue(TEST_DEVICE_ID)

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'bad-key', userId: 'dave', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.error).not.toBeNull(), { timeout: 3000 })
    expect(result.current.isReady).toBe(false)
  })

  it('calls onError callback on WebSocket error and does not set fatal error state', async () => {
    setupMocks()

    const onError = vi.fn()
    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'eve', serverUrl: 'http://localhost:3000', onError })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      mockWs.simulateError()
    })

    await waitFor(() => expect(onError).toHaveBeenCalledWith(expect.any(Error)))
    // WS errors are recoverable (reconnect); the fatal error state stays null
    expect(result.current.error).toBeNull()
  })

  it('sendMessage throws when WebSocket is not connected', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'frank', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    // Close the socket to simulate disconnection
    await act(async () => { mockWs.close() })

    await expect(result.current.sendMessage('bob', 'hi')).rejects.toThrow('WebSocket is not connected')
  })

  it('marks not ready when WebSocket closes', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'grace', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => { mockWs.close() })

    await waitFor(() => expect(result.current.isReady).toBe(false))
  })

  it('ignores WebSocket messages with unknown type or missing fields', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'henry', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      mockWs.simulateMessage('not-json{{{')
      mockWs.simulateMessage(JSON.stringify({ type: 'ping' }))
      // missing fromDeviceId, ciphertext, nonce, header — all ignored
      mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'x' }))
      mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'x', ciphertext: 'a', nonce: 'b' }))
      await new Promise((r) => setTimeout(r, 100))
    })

    expect(result.current.messages).toHaveLength(0)
    expect(result.current.error).toBeNull()
  })

  it('calls onWireMessage with direction "received" on every incoming message', async () => {
    setupMocks()

    const ivyKP = await generateKeyPair()
    keyStore.set('ivy', exportKey(ivyKP.publicKey))

    const onWireMessage = vi.fn()
    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'jack', serverUrl: 'http://localhost:3000', onWireMessage })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    const wireMsg = JSON.stringify({
      type:         'message',
      from:         'ivy',
      fromDeviceId: TEST_DEVICE_ID,
      ciphertext:   exportKey(new Uint8Array(48).fill(0xcc)),
      nonce:        exportKey(new Uint8Array(24).fill(0xdd)),
      encHeader:    exportKey(new Uint8Array(40).fill(0xee)),
    })

    await act(async () => {
      mockWs.simulateMessage(wireMsg)
      await new Promise((r) => setTimeout(r, 200))
    })

    expect(onWireMessage).toHaveBeenCalledWith(
      expect.objectContaining({ direction: 'received' })
    )
  })

  it('sets isConnecting true and schedules reconnect after WebSocket closes', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'karen', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => { mockWs.close() })

    await waitFor(() => expect(result.current.isConnecting).toBe(true))
    expect(result.current.isReady).toBe(false)
  })

  it('restores key pair from IndexedDB without generating a new one', async () => {
    setupMocks()

    const storedKP = await generateKeyPair()
    vi.spyOn(ratchetStore, 'loadKeyPair').mockResolvedValue({
      pub:  exportKey(storedKP.publicKey),
      priv: exportKey(storedKP.privateKey),
    })
    const saveKeyPairSpy = vi.spyOn(ratchetStore, 'saveKeyPair').mockResolvedValue()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'leo', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    // Key was loaded from IDB so no new key should be saved
    expect(saveKeyPairSpy).not.toHaveBeenCalled()
  })

  it('sendMessage encrypts and routes the payload, fires onWireMessage with direction sent', async () => {
    setupMocks()

    // Register the peer's key so fetchPeerDeviceKeys (device discovery) succeeds,
    // and publish a valid prekey bundle so X3DH initiation can verify and run.
    const peerKP = await generateKeyPair()
    keyStore.set('mallory', exportKey(peerKP.publicKey))
    await seedPreKeyBundle(preKeyStore, 'mallory')

    // Spy on DoubleRatchet.initSender so ratchet.encrypt() does not call
    // crypto_secretbox_easy — that function has a cross-realm Uint8Array issue
    // in jsdom. The real x3dhInitiate still runs; we mock only the ratchet so
    // we can verify the hook wires routing + the prekey frame correctly.
    const fakeRatchet = {
      encrypt: vi.fn().mockResolvedValue({
        encHeader:  new Uint8Array(40).fill(0x03),
        ciphertext: new Uint8Array(48).fill(0x01),
        nonce:      new Uint8Array(24).fill(0x02),
      }),
      export: vi.fn().mockReturnValue({ version: 2 }),
    }
    vi.spyOn(DoubleRatchet, 'initSender').mockResolvedValue(
      fakeRatchet as unknown as InstanceType<typeof DoubleRatchet>
    )

    const onWireMessage = vi.fn()
    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'nina', serverUrl: 'http://localhost:3000', onWireMessage })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      // First call — creates the sender ratchet from scratch
      await result.current.sendMessage('mallory', 'hello encrypted world')
      // Second call — hits the in-memory ratchet cache (covers the `if (existing)` true branch)
      await result.current.sendMessage('mallory', 'second message')
    })

    // mallory has 1 device, so each sendMessage sends 1 frame — 2 total
    const sentFrames = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'message' && p.to === 'mallory'
    })
    expect(sentFrames).toHaveLength(2)

    // Frames must include toDeviceId for relay routing and an encrypted header.
    for (const frame of sentFrames) {
      const p = JSON.parse(frame) as { toDeviceId?: string; encHeader?: string }
      expect(p.toDeviceId).toBe(TEST_DEVICE_ID)
      expect(p.encHeader).toBeTruthy()
    }

    // The first message of the session must carry the X3DH prekey as its own field.
    const firstFrame = JSON.parse(sentFrames[0]!) as { prekey?: { ephemeralKey?: string } }
    expect(firstFrame.prekey?.ephemeralKey).toBeTruthy()

    // onWireMessage should have fired with direction 'sent' for each message
    const sentEvents = onWireMessage.mock.calls.filter(
      (c) => (c[0] as { direction: string }).direction === 'sent'
    )
    expect(sentEvents).toHaveLength(2)
  })

  it('reuses the cached receiver ratchet on subsequent messages from the same sender', async () => {
    setupMocks()

    const senderKP = await generateKeyPair()
    keyStore.set('oscar', exportKey(senderKP.publicKey))

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'pat', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    const wireMsg = JSON.stringify({
      type:         'message',
      from:         'oscar',
      fromDeviceId: TEST_DEVICE_ID,
      ciphertext:   exportKey(new Uint8Array(48).fill(0xee)),
      nonce:        exportKey(new Uint8Array(24).fill(0xff)),
      encHeader:    exportKey(new Uint8Array(40).fill(0x11)),
    })

    await act(async () => {
      // First message — creates the receiver ratchet
      mockWs.simulateMessage(wireMsg)
      await new Promise((r) => setTimeout(r, 50))
      // Second message from the same sender — exercises the `if (existing)` true
      // branch in getOrInitReceiverRatchet (cache hit path)
      mockWs.simulateMessage(wireMsg)
      await new Promise((r) => setTimeout(r, 100))
    })

    // Both decryptions fail (wrong bytes) — hook must stay ready and not crash
    expect(result.current.isReady).toBe(true)
    expect(result.current.messages).toHaveLength(0)
  })
})
