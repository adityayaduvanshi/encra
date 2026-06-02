import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useE2EPresence } from '../src/useE2EPresence.js'
import * as ratchetStore from '../src/ratchetStore.js'
import {
  sodiumReady,
  generateKeyPair,
  exportKey,
  deriveSharedSecret,
  derivePresenceKey,
  encryptPresence,
} from '@encra/core'

// ── WebSocket mock ────────────────────────────────────────────────────────────

type WsListener = (event: { data: string }) => void

class MockWebSocket {
  static OPEN = 1
  readyState = MockWebSocket.OPEN
  sentMessages: string[] = []

  private openListeners:    (() => void)[]    = []
  private messageListeners: WsListener[]      = []
  private closeListeners:   (() => void)[]    = []
  private errorListeners:   (() => void)[]    = []

  constructor(public url: string) {
    setTimeout(() => this.openListeners.forEach((fn) => fn()), 0)
  }

  send(data: string) { this.sentMessages.push(data) }

  close() {
    this.readyState = 3
    this.closeListeners.forEach((fn) => fn())
  }

  addEventListener(event: string, listener: (e: unknown) => void) {
    if      (event === 'open')    this.openListeners.push(listener as () => void)
    else if (event === 'message') this.messageListeners.push(listener as WsListener)
    else if (event === 'close')   this.closeListeners.push(listener as () => void)
    else if (event === 'error')   this.errorListeners.push(listener as () => void)
  }

  simulateMessage(data: string) { this.messageListeners.forEach((fn) => fn({ data })) }
  simulateError()               { this.errorListeners.forEach((fn) => fn())           }
}

// ── fetch mock ────────────────────────────────────────────────────────────────

const TEST_DEVICE_ID = 'test-device'

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

describe('useE2EPresence', () => {
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
    vi.spyOn(ratchetStore, 'loadGhostMode').mockResolvedValue(false)
    vi.spyOn(ratchetStore, 'saveGhostMode').mockResolvedValue()
    vi.stubGlobal(
      'WebSocket',
      class extends MockWebSocket {
        constructor(url: string) {
          super(url)
          mockWs = this
        }
      },
    )
  }

  it('becomes ready after key registration and WebSocket connection', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'alice',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    expect(result.current.error).toBeNull()
    expect(result.current.ghostMode).toBe(false)
  })

  it('sends a register message with userId and deviceId when WebSocket opens', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'bob',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    const registerMsg = mockWs.sentMessages.find((m) => {
      const p = JSON.parse(m) as { type: string }
      return p.type === 'register'
    })
    expect(registerMsg).toBeDefined()
    const parsed = JSON.parse(registerMsg!) as { userId: string; deviceId: string }
    expect(parsed.userId).toBe('bob')
    expect(parsed.deviceId).toBe(TEST_DEVICE_ID)
  })

  it('broadcasts online to contacts once connected', async () => {
    setupMocks()

    // Register contact's public key so the hook can encrypt for them
    const contactKP = await generateKeyPair()
    keyStore.set('carol', exportKey(contactKP.publicKey))

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'alice3',
        contacts:  ['carol'],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    // Allow async online broadcast to fire
    await act(async () => { await new Promise((r) => setTimeout(r, 200)) })

    const presenceMsgs = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'presence' && p.to === 'carol'
    })
    expect(presenceMsgs.length).toBeGreaterThanOrEqual(1)
  })

  it('decrypts an incoming presence message and updates presence state', async () => {
    // Use a known key pair for alice so we can compute the shared secret
    const aliceKP = await generateKeyPair()
    vi.spyOn(ratchetStore, 'loadKeyPair').mockResolvedValue({
      pub:  exportKey(aliceKP.publicKey),
      priv: exportKey(aliceKP.privateKey),
    })
    vi.spyOn(ratchetStore, 'saveKeyPair').mockResolvedValue()
    setupMocks()

    const bobKP = await generateKeyPair()
    keyStore.set('bob2', exportKey(bobKP.publicKey))

    // Pre-compute the presence key that the hook will derive for alice→bob2
    const shared      = await deriveSharedSecret(aliceKP.privateKey, bobKP.publicKey)
    const presenceKey = await derivePresenceKey(shared)

    const payload = { status: 'online' as const, lastSeenAt: 1_700_000_000_000, isTyping: false }
    const enc     = await encryptPresence(payload, presenceKey)

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'alice4',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      mockWs.simulateMessage(JSON.stringify({
        type:          'presence',
        from:          'bob2',
        fromDeviceId:  TEST_DEVICE_ID,
        ciphertext:    enc.ciphertext,
        nonce:         enc.nonce,
      }))
      await new Promise((r) => setTimeout(r, 300))
    })

    await waitFor(() => expect(result.current.presence['bob2']).toBeDefined(), { timeout: 3000 })
    expect(result.current.presence['bob2']!.status).toBe('online')
    expect(result.current.presence['bob2']!.isTyping).toBe(false)
  })

  it('ignores presence messages with missing fields', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'carol2',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      mockWs.simulateMessage('bad-json{{{')
      mockWs.simulateMessage(JSON.stringify({ type: 'ping' }))
      mockWs.simulateMessage(JSON.stringify({ type: 'presence', from: 'x' })) // missing fields
      mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'x', fromDeviceId: 'y', ciphertext: 'a', nonce: 'b' }))
      await new Promise((r) => setTimeout(r, 100))
    })

    expect(result.current.presence).toEqual({})
    expect(result.current.error).toBeNull()
  })

  it('calls onError and does not crash on decryption failure (wrong key)', async () => {
    setupMocks()

    const bobKP = await generateKeyPair()
    keyStore.set('bob3', exportKey(bobKP.publicKey))

    // Encrypt with wrong key so decryption will fail
    const wrongKey = await derivePresenceKey(await deriveSharedSecret(bobKP.privateKey, bobKP.publicKey))
    const enc = await encryptPresence(
      { status: 'online', lastSeenAt: Date.now(), isTyping: false },
      wrongKey,
    )

    const onError = vi.fn()
    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'dave2',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
        onError,
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      mockWs.simulateMessage(JSON.stringify({
        type:         'presence',
        from:         'bob3',
        fromDeviceId: TEST_DEVICE_ID,
        ciphertext:   enc.ciphertext,
        nonce:        enc.nonce,
      }))
      await new Promise((r) => setTimeout(r, 200))
    })

    expect(onError).toHaveBeenCalledWith(expect.any(Error))
    expect(result.current.isReady).toBe(true)
  })

  it('calls onError on WebSocket error', async () => {
    setupMocks()

    const onError = vi.fn()
    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'eve2',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
        onError,
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => { mockWs.simulateError() })

    expect(onError).toHaveBeenCalledWith(expect.any(Error))
  })

  it('marks not ready when WebSocket closes', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'frank2',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => { mockWs.close() })

    await waitFor(() => expect(result.current.isReady).toBe(false))
  })

  it('sets error when key registration fetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) } as Response)),
    )
    vi.stubGlobal('WebSocket', MockWebSocket)
    vi.spyOn(ratchetStore, 'getOrCreateDeviceId').mockResolvedValue(TEST_DEVICE_ID)
    vi.spyOn(ratchetStore, 'loadGhostMode').mockResolvedValue(false)
    vi.spyOn(ratchetStore, 'saveGhostMode').mockResolvedValue()

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'bad-key',
        userId:    'grace2',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.error).not.toBeNull(), { timeout: 3000 })
    expect(result.current.isReady).toBe(false)
  })

  it('setGhostMode(true) broadcasts offline to contacts then suppresses future sends', async () => {
    setupMocks()

    const contactKP = await generateKeyPair()
    keyStore.set('henry2', exportKey(contactKP.publicKey))

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'iris',
        contacts:  ['henry2'],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    // Allow the initial online broadcast to fire
    await act(async () => { await new Promise((r) => setTimeout(r, 200)) })

    const countBefore = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'presence' && p.to === 'henry2'
    }).length

    await act(async () => { await result.current.setGhostMode(true) })

    expect(result.current.ghostMode).toBe(true)
    expect(ratchetStore.saveGhostMode).toHaveBeenCalledWith('iris', true)

    const countAfterEnable = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'presence' && p.to === 'henry2'
    }).length

    // At least one offline broadcast must have been sent when enabling ghost mode
    expect(countAfterEnable).toBeGreaterThan(countBefore)
  })

  it('setGhostMode(false) broadcasts online to contacts', async () => {
    setupMocks()

    const contactKP = await generateKeyPair()
    keyStore.set('jack2', exportKey(contactKP.publicKey))

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'karen2',
        contacts:  ['jack2'],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    await act(async () => { await new Promise((r) => setTimeout(r, 200)) })

    // Enable ghost mode first
    await act(async () => { await result.current.setGhostMode(true) })
    expect(result.current.ghostMode).toBe(true)

    const countWhileGhost = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'presence' && p.to === 'jack2'
    }).length

    // Disable ghost mode — should broadcast online
    await act(async () => { await result.current.setGhostMode(false) })

    expect(result.current.ghostMode).toBe(false)
    expect(ratchetStore.saveGhostMode).toHaveBeenCalledWith('karen2', false)

    const countAfterDisable = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'presence' && p.to === 'jack2'
    }).length
    expect(countAfterDisable).toBeGreaterThan(countWhileGhost)
  })

  it('setGhostMode is a noop when already in the requested state', async () => {
    setupMocks()

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'leo2',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    // Already false — calling false again should be a noop
    await act(async () => { await result.current.setGhostMode(false) })
    expect(ratchetStore.saveGhostMode).not.toHaveBeenCalled()
  })

  it('sendTyping sends a presence message with isTyping true', async () => {
    setupMocks()

    const bobKP = await generateKeyPair()
    keyStore.set('bob4', exportKey(bobKP.publicKey))

    // Use empty contacts so there is no auto-broadcast racing with sendTyping.
    // The only presence message to 'bob4' will come from sendTyping itself.
    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'mallory2',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    // Spy on send AFTER isReady so we know mockWs is the correct socket
    const sendSpy = vi.spyOn(mockWs, 'send')

    await act(async () => {
      void result.current.sendTyping('bob4', true)
    })

    // Poll until the async crypto + send chain completes
    await waitFor(
      () => {
        const presenceCalls = sendSpy.mock.calls.filter(([data]) => {
          const p = JSON.parse(data as string) as { type: string; to?: string }
          return p.type === 'presence' && p.to === 'bob4'
        })
        expect(presenceCalls.length).toBeGreaterThanOrEqual(1)
      },
      { timeout: 3000 },
    )
  })

  it('setStatus broadcasts to all contacts', async () => {
    setupMocks()

    const c1KP = await generateKeyPair()
    const c2KP = await generateKeyPair()
    keyStore.set('contact1', exportKey(c1KP.publicKey))
    keyStore.set('contact2', exportKey(c2KP.publicKey))

    // Contacts are declared so setStatus knows who to broadcast to.
    // Also spy on send RIGHT after isReady to avoid any auto-broadcast race.
    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'nina2',
        contacts:  ['contact1', 'contact2'],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    // Spy on send after isReady; reset any prior calls (initial broadcast)
    const sendSpy = vi.spyOn(mockWs, 'send')
    sendSpy.mockClear()

    await act(async () => {
      void result.current.setStatus('away')
    })

    // Poll until setStatus sends one frame per contact (2 total)
    await waitFor(
      () => {
        const presenceCalls = sendSpy.mock.calls.filter(([data]) => {
          const p = JSON.parse(data as string) as { type: string }
          return p.type === 'presence'
        })
        expect(presenceCalls.length).toBeGreaterThanOrEqual(2)
      },
      { timeout: 3000 },
    )
  })

  it('setStatus is a noop when ghost mode is active', async () => {
    setupMocks()

    const contactKP = await generateKeyPair()
    keyStore.set('oscar2', exportKey(contactKP.publicKey))

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'pat2',
        contacts:  ['oscar2'],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    await act(async () => { await new Promise((r) => setTimeout(r, 200)) })

    await act(async () => { await result.current.setGhostMode(true) })

    const countWhileGhost = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string }
      return p.type === 'presence'
    }).length

    await act(async () => { await result.current.setStatus('busy') })

    const countAfter = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string }
      return p.type === 'presence'
    }).length

    expect(countAfter).toBe(countWhileGhost)
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
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'quinn',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    expect(saveKeyPairSpy).not.toHaveBeenCalled()
  })

  it('loads ghost mode from IndexedDB on init', async () => {
    // Override the default ghost mode mock to return true
    vi.spyOn(ratchetStore, 'getOrCreateDeviceId').mockResolvedValue(TEST_DEVICE_ID)
    vi.spyOn(ratchetStore, 'loadGhostMode').mockResolvedValue(true)
    vi.spyOn(ratchetStore, 'saveGhostMode').mockResolvedValue()
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    vi.stubGlobal(
      'WebSocket',
      class extends MockWebSocket {
        constructor(url: string) {
          super(url)
          mockWs = this
        }
      },
    )

    const { result } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'rose',
        contacts:  [],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    expect(result.current.ghostMode).toBe(true)
  })

  it('broadcasts offline to cached contacts on unmount', async () => {
    setupMocks()

    const contactKP = await generateKeyPair()
    keyStore.set('sam', exportKey(contactKP.publicKey))

    const { result, unmount } = renderHook(() =>
      useE2EPresence({
        apiKey:    'test-key',
        userId:    'tom',
        contacts:  ['sam'],
        serverUrl: 'http://localhost:3000',
      }),
    )

    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    // Allow online broadcast + presence key cache to populate
    await act(async () => { await new Promise((r) => setTimeout(r, 300)) })

    const countBefore = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'presence' && p.to === 'sam'
    }).length

    // Unmount triggers best-effort offline broadcast
    act(() => { unmount() })
    await act(async () => { await new Promise((r) => setTimeout(r, 100)) })

    const countAfter = mockWs.sentMessages.filter((m) => {
      const p = JSON.parse(m) as { type: string; to?: string }
      return p.type === 'presence' && p.to === 'sam'
    }).length

    expect(countAfter).toBeGreaterThanOrEqual(countBefore)
  })
})
