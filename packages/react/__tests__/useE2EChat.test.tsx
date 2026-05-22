import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useE2EChat } from '../src/useE2EChat.js'
import {
  sodiumReady,
  generateKeyPair,
  deriveSharedSecret,
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

  it('sets error and marks not ready on WebSocket error', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EChat({ apiKey: 'test-key', userId: 'eve', serverUrl: 'http://localhost:3000' })
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      mockWs.simulateError()
    })

    await waitFor(() => expect(result.current.error).not.toBeNull())
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
})
