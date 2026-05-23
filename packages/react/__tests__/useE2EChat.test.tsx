import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useE2EChat } from '../src/useE2EChat.js'
import * as ratchetStore from '../src/ratchetStore.js'
import {
  sodiumReady,
  generateKeyPair,
  DoubleRatchet,
  exportKey,
  importKey,
} from '@encra/core'
import sodium from 'libsodium-wrappers'

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
    if (event === 'open') this.openListeners.push(listener as () => void)
    else if (event === 'message') this.messageListeners.push(listener as WsListener)
    else if (event === 'close') this.closeListeners.push(listener as () => void)
    else if (event === 'error') this.errorListeners.push(listener as () => void)
  }

  simulateMessage(data: string) {
    this.messageListeners.forEach((fn) => fn({ data }))
  }

  simulateError() {
    this.errorListeners.forEach((fn) => fn())
  }
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
      if (key) {
        return { ok: true, status: 200, json: async () => ({ userId: uid, publicKey: key }) } as Response
      }
      return { ok: false, status: 404, json: async () => ({ error: 'not found' }) } as Response
    }

    return { ok: false, status: 404 } as Response
  })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('useE2EChat', () => {
  const keyStore = new Map<string, string>()
  let mockWs: MockWebSocket

  beforeAll(async () => {
    await sodiumReady()
  })

  afterEach(() => {
    keyStore.clear()
    vi.restoreAllMocks()
  })

  function setupMocks() {
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    vi.stubGlobal(
      'WebSocket',
      class extends MockWebSocket {
        constructor(url: string) {
          super(url)
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

  it('sends a register message when WebSocket opens', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'bob', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    const registerMsg = mockWs.sentMessages.find((m) => {
      const parsed = JSON.parse(m) as { type: string; userId?: string }
      return parsed.type === 'register' && parsed.userId === 'bob'
    })
    expect(registerMsg).toBeDefined()
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

    // Send a message with arbitrary bytes — decryption will fail (wrong shared secret),
    // but the hook must still attempt to fetch Carol's public key (cache miss path)
    // and handle the DecryptionFailedError without crashing.
    // A header is required by the new ratchet-aware hook.
    const wireMsg = JSON.stringify({
      type: 'message',
      from: 'carol',
      ciphertext: exportKey(new Uint8Array(48).fill(0xaa)),
      nonce: exportKey(new Uint8Array(24).fill(0xbb)),
      header: { dh: exportKey(carolKP.publicKey), pn: 0, n: 0 },
    })

    await act(async () => {
      mockWs.simulateMessage(wireMsg)
      await new Promise((r) => setTimeout(r, 200))
    })

    // Hook should have tried to fetch Carol's key (verifiable via fetch mock call count)
    const fetchMock = vi.mocked(globalThis.fetch as ReturnType<typeof vi.fn>)
    const keyFetch = fetchMock.mock.calls.find(
      (call) => typeof call[0] === 'string' && (call[0] as string).includes('/v1/keys/carol')
    )
    expect(keyFetch).toBeDefined()

    // Decryption failed (wrong bytes), so no message should be in state
    expect(result.current.messages).toHaveLength(0)
    // Hook must remain functional after a decryption failure
    expect(result.current.isReady).toBe(true)
  })

  it('sets error when fetch registration fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) } as Response))
    )
    vi.stubGlobal('WebSocket', MockWebSocket)

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
      mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'x' })) // missing ciphertext/nonce/header
      mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'x', ciphertext: 'a', nonce: 'b' })) // missing header
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
      type: 'message',
      from: 'ivy',
      ciphertext: exportKey(new Uint8Array(48).fill(0xcc)),
      nonce: exportKey(new Uint8Array(24).fill(0xdd)),
      header: { dh: exportKey(ivyKP.publicKey), pn: 0, n: 0 },
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

    // Register the peer's key so fetchPeerPublicKey succeeds
    const peerKP = await generateKeyPair()
    keyStore.set('mallory', exportKey(peerKP.publicKey))

    // Spy on DoubleRatchet.initSender so ratchet.encrypt() does not call
    // crypto_secretbox_easy — that function has a cross-realm Uint8Array issue
    // in jsdom.  We just need to verify the hook wires things up correctly.
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

    // The socket should have received two 'message' frames addressed to mallory
    const sentFrames = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'message' && p.to === 'mallory'
    })
    expect(sentFrames).toHaveLength(2)

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
      type: 'message',
      from: 'oscar',
      ciphertext: exportKey(new Uint8Array(48).fill(0xee)),
      nonce: exportKey(new Uint8Array(24).fill(0xff)),
      header: { dh: exportKey(senderKP.publicKey), pn: 0, n: 0 },
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
