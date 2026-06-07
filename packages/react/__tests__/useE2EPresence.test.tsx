import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useE2EPresence } from '../src/useE2EPresence.js'
import * as ratchetStore from '../src/ratchetStore.js'
import {
  sodiumReady,
  generateKeyPair,
  exportKey,
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  buildPreKeyBundle,
  x3dhInitiate,
  x3dhRespond,
  derivePresenceKey,
  encryptPresence,
  decryptPresence,
} from '@encra/core'
import type { IdentityKeyPair, KeyPair, PreKeyBundle, PreKeyMessage } from '@encra/core'

// ── WebSocket mock ────────────────────────────────────────────────────────────

type WsListener = (event: { data: string }) => void

class MockWebSocket {
  static OPEN = 1
  readyState = MockWebSocket.OPEN
  sentMessages: string[] = []

  private openListeners:    (() => void)[] = []
  private messageListeners: WsListener[]   = []
  private closeListeners:   (() => void)[] = []
  private errorListeners:   (() => void)[] = []

  constructor(public url: string) {
    setTimeout(() => this.openListeners.forEach((fn) => fn()), 0)
  }

  send(data: string) { this.sentMessages.push(data) }
  close() { this.readyState = 3; this.closeListeners.forEach((fn) => fn()) }

  addEventListener(event: string, listener: (e: unknown) => void) {
    if      (event === 'open')    this.openListeners.push(listener as () => void)
    else if (event === 'message') this.messageListeners.push(listener as WsListener)
    else if (event === 'close')   this.closeListeners.push(listener as () => void)
    else if (event === 'error')   this.errorListeners.push(listener as () => void)
  }

  simulateMessage(data: string) { this.messageListeners.forEach((fn) => fn({ data })) }
  parsedSends() { return this.sentMessages.map((m) => JSON.parse(m) as Record<string, unknown>) }
  presenceSends() { return this.parsedSends().filter((m) => m['type'] === 'presence') }
}

// ── fetch mock: /v1/keys + /v1/prekeys ──────────────────────────────────────────

const TEST_DEVICE_ID = 'test-device'

interface StoredBundle { bundle: PreKeyBundle }

function makeFetchMock(keyStore: Map<string, string>, bundleStore: Map<string, StoredBundle>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    const ok  = (body: unknown, status = 200) =>
      ({ ok: true, status, json: async () => body } as Response)
    const notFound = () => ({ ok: false, status: 404, json: async () => ({}) } as Response)

    // POST /v1/keys
    if (url.endsWith('/v1/keys') && init?.method === 'POST') {
      const body = JSON.parse(init.body as string) as { userId: string; publicKey: string; deviceId?: string }
      keyStore.set(body.userId, body.publicKey)
      return ok({ userId: body.userId, deviceId: body.deviceId ?? TEST_DEVICE_ID }, 201)
    }

    // POST /v1/prekeys — capture the published bundle
    if (url.endsWith('/v1/prekeys') && init?.method === 'POST') {
      const b = JSON.parse(init.body as string) as {
        userId: string; deviceId: string
        identityKey: string
        signedPreKey: { keyId: number; publicKey: string; signature: string }
      }
      bundleStore.set(`${b.userId}:${b.deviceId}`, {
        bundle: { identityKey: b.identityKey, signedPreKey: b.signedPreKey },
      })
      return ok({ userId: b.userId, deviceId: b.deviceId, oneTimePreKeyCount: 0 }, 201)
    }

    // GET /v1/prekeys/:userId/:deviceId  (presence uses ?consumeOneTime=false)
    const pk = url.match(/\/v1\/prekeys\/([^/?]+)\/([^/?]+)/)
    if (pk) {
      const entry = bundleStore.get(`${decodeURIComponent(pk[1]!)}:${decodeURIComponent(pk[2]!)}`)
      return entry ? ok(entry.bundle) : notFound()
    }

    // GET /v1/keys/:userId
    const km = url.match(/\/v1\/keys\/([^/?]+)$/)
    if (km) {
      const uid = decodeURIComponent(km[1]!)
      const key = keyStore.get(uid)
      return key
        ? ok({ userId: uid, devices: [{ deviceId: TEST_DEVICE_ID, publicKey: key }] })
        : notFound()
    }

    return notFound()
  })
}

// ── Synthetic peer (acts as the other side of an X3DH presence session) ─────────

interface Peer {
  userId:    string
  identity:  IdentityKeyPair
  signedPair: KeyPair
  bundle:    PreKeyBundle
}

async function makePeer(userId: string): Promise<Peer> {
  const identity = await generateIdentityKeyPair()
  const spk      = await generateSignedPreKey(identity, 1)
  const bundle   = buildPreKeyBundle(identity, spk)
  return { userId, identity, signedPair: spk.keyPair, bundle }
}

describe('useE2EPresence', () => {
  const keyStore    = new Map<string, string>()
  const bundleStore = new Map<string, StoredBundle>()
  let mockWs: MockWebSocket

  beforeAll(async () => { await sodiumReady() })

  afterEach(() => {
    keyStore.clear()
    bundleStore.clear()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  function setupMocks() {
    vi.stubGlobal('fetch', makeFetchMock(keyStore, bundleStore))
    vi.spyOn(ratchetStore, 'getOrCreateDeviceId').mockResolvedValue(TEST_DEVICE_ID)
    // Spy but call through to the real (jsdom: IndexedDB-unavailable) implementations
    // so their no-op paths are exercised, while still recording calls.
    vi.spyOn(ratchetStore, 'loadGhostMode')
    vi.spyOn(ratchetStore, 'saveGhostMode')
    vi.stubGlobal('WebSocket', class extends MockWebSocket {
      constructor(url: string) { super(url); mockWs = this }
    })
  }

  /** Register a synthetic peer's device key + prekey bundle in the mock server. */
  async function publishPeer(peer: Peer) {
    const kp = await generateKeyPair()
    keyStore.set(peer.userId, exportKey(kp.publicKey))
    bundleStore.set(`${peer.userId}:${TEST_DEVICE_ID}`, { bundle: peer.bundle })
  }

  function render(opts: { userId: string; contacts: string[]; onError?: (e: Error) => void }) {
    return renderHook(() =>
      useE2EPresence({ apiKey: 'test-key', serverUrl: 'http://localhost:3000', ...opts }),
    )
  }

  it('becomes ready after key registration and WebSocket connection', async () => {
    setupMocks()
    const { result } = render({ userId: 'alice', contacts: [] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    expect(result.current.error).toBeNull()
    expect(result.current.ghostMode).toBe(false)
  })

  it('sends an auth then register message when the WebSocket opens', async () => {
    setupMocks()
    const { result } = render({ userId: 'bob', contacts: [] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    const types = mockWs.parsedSends().map((m) => m['type'])
    expect(types[0]).toBe('auth')
    const reg = mockWs.parsedSends().find((m) => m['type'] === 'register')!
    expect(reg['userId']).toBe('bob')
    expect(reg['deviceId']).toBe(TEST_DEVICE_ID)
  })

  it('broadcasts an encrypted, decryptable online status to contacts on connect', async () => {
    setupMocks()
    const carol = await makePeer('carol')
    await publishPeer(carol)

    const { result } = render({ userId: 'alice', contacts: ['carol'] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    await waitFor(() => expect(mockWs.presenceSends().length).toBeGreaterThan(0), { timeout: 3000 })

    const frame = mockWs.presenceSends()[0]!
    expect(frame['to']).toBe('carol')
    expect(frame['ciphertext']).toBeTruthy()
    expect(frame['nonce']).toBeTruthy()
    expect(frame['prekey']).toBeTruthy()

    // Carol decrypts it by responding to the X3DH prekey, exactly as her hook would.
    const keys = await x3dhRespond(carol.identity, carol.signedPair, null, frame['prekey'] as PreKeyMessage)
    const pKey = await derivePresenceKey(keys.rootKey)
    const payload = await decryptPresence(
      { ciphertext: frame['ciphertext'] as string, nonce: frame['nonce'] as string },
      pKey,
    )
    expect(payload.status).toBe('online')
    expect(payload.isTyping).toBe(false)
  })

  it('updates the presence map when an encrypted inbound update arrives', async () => {
    setupMocks()
    const { result } = render({ userId: 'alice', contacts: [] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    // Alice published her bundle on connect; "bob" initiates a presence session to her.
    const aliceBundle = bundleStore.get(`alice:${TEST_DEVICE_ID}`)!.bundle
    const bobIdentity = await generateIdentityKeyPair()
    const init = await x3dhInitiate(bobIdentity, aliceBundle)
    const pKey = await derivePresenceKey(init.sessionKeys.rootKey)
    const enc  = await encryptPresence({ status: 'away', lastSeenAt: 123, isTyping: true }, pKey)

    await act(async () => {
      mockWs.simulateMessage(JSON.stringify({
        type: 'presence', from: 'bob', fromDeviceId: TEST_DEVICE_ID,
        ciphertext: enc.ciphertext, nonce: enc.nonce, prekey: init.message,
      }))
    })

    await waitFor(() => expect(result.current.presence['bob']?.status).toBe('away'), { timeout: 3000 })
    expect(result.current.presence['bob']?.isTyping).toBe(true)
    expect(result.current.presence['bob']?.lastSeenAt).toBe(123)
  })

  it('sendTyping sends an update with isTyping true', async () => {
    setupMocks()
    const carol = await makePeer('carol')
    await publishPeer(carol)

    const { result } = render({ userId: 'alice', contacts: [] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => { await result.current.sendTyping('carol', true) })

    const frame = mockWs.presenceSends().find((m) => m['to'] === 'carol')!
    const keys  = await x3dhRespond(carol.identity, carol.signedPair, null, frame['prekey'] as PreKeyMessage)
    const pKey  = await derivePresenceKey(keys.rootKey)
    const payload = await decryptPresence(
      { ciphertext: frame['ciphertext'] as string, nonce: frame['nonce'] as string }, pKey,
    )
    expect(payload.isTyping).toBe(true)
  })

  it('ghost mode broadcasts offline, suppresses further updates, and persists', async () => {
    setupMocks()
    const carol = await makePeer('carol')
    await publishPeer(carol)

    const { result } = render({ userId: 'alice', contacts: ['carol'] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    await waitFor(() => expect(mockWs.presenceSends().length).toBeGreaterThan(0), { timeout: 3000 })

    await act(async () => { await result.current.setGhostMode(true) })
    expect(result.current.ghostMode).toBe(true)
    expect(ratchetStore.saveGhostMode).toHaveBeenCalledWith('alice', true)

    const countAfterGhost = mockWs.presenceSends().length
    await act(async () => { await result.current.setStatus('busy') })
    // setStatus is a no-op in ghost mode — no new frames.
    expect(mockWs.presenceSends().length).toBe(countAfterGhost)
  })

  it('setStatus broadcasts the given status to every contact', async () => {
    setupMocks()
    const carol = await makePeer('carol')
    await publishPeer(carol)

    const { result } = render({ userId: 'alice', contacts: ['carol'] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => { await result.current.setStatus('away') })

    // Use the most recent carol frame — the first is the auto online broadcast.
    const carolFrames = mockWs.presenceSends().filter((m) => m['to'] === 'carol')
    const frame = carolFrames[carolFrames.length - 1]!
    const keys  = await x3dhRespond(carol.identity, carol.signedPair, null, frame['prekey'] as PreKeyMessage)
    const pKey  = await derivePresenceKey(keys.rootKey)
    const payload = await decryptPresence(
      { ciphertext: frame['ciphertext'] as string, nonce: frame['nonce'] as string }, pKey,
    )
    expect(payload.status).toBe('away')
  })

  it('disabling ghost mode re-broadcasts online and persists the flag', async () => {
    setupMocks()
    const carol = await makePeer('carol')
    await publishPeer(carol)

    const { result } = render({ userId: 'alice', contacts: ['carol'] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => { await result.current.setGhostMode(true) })
    expect(result.current.ghostMode).toBe(true)

    await act(async () => { await result.current.setGhostMode(false) })
    expect(result.current.ghostMode).toBe(false)
    expect(ratchetStore.saveGhostMode).toHaveBeenLastCalledWith('alice', false)

    // The last frame sent after re-enabling should decrypt to an online status.
    const frames = mockWs.presenceSends().filter((m) => m['to'] === 'carol')
    const last   = frames[frames.length - 1]!
    const keys   = await x3dhRespond(carol.identity, carol.signedPair, null, last['prekey'] as PreKeyMessage)
    const pKey   = await derivePresenceKey(keys.rootKey)
    const payload = await decryptPresence(
      { ciphertext: last['ciphertext'] as string, nonce: last['nonce'] as string }, pKey,
    )
    expect(payload.status).toBe('online')
  })

  it('broadcasts offline to established contacts on unmount', async () => {
    setupMocks()
    const carol = await makePeer('carol')
    await publishPeer(carol)

    const { result, unmount } = render({ userId: 'alice', contacts: ['carol'] })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })
    await waitFor(() => expect(mockWs.presenceSends().length).toBeGreaterThan(0), { timeout: 3000 })

    const before = mockWs.presenceSends().length
    unmount()
    await waitFor(() => expect(mockWs.presenceSends().length).toBeGreaterThan(before), { timeout: 3000 })

    const last = mockWs.presenceSends()[mockWs.presenceSends().length - 1]!
    const keys = await x3dhRespond(carol.identity, carol.signedPair, null, last['prekey'] as PreKeyMessage)
    const pKey = await derivePresenceKey(keys.rootKey)
    const payload = await decryptPresence(
      { ciphertext: last['ciphertext'] as string, nonce: last['nonce'] as string }, pKey,
    )
    expect(payload.status).toBe('offline')
  })

  it('ignores non-presence and malformed inbound frames', async () => {
    setupMocks()
    const onError = vi.fn()
    const { result } = render({ userId: 'alice', contacts: [], onError })
    await waitFor(() => expect(result.current.isReady).toBe(true), { timeout: 3000 })

    await act(async () => {
      mockWs.simulateMessage(JSON.stringify({ type: 'message', from: 'bob' }))
      mockWs.simulateMessage('not-json{{{')
      mockWs.simulateMessage(JSON.stringify({ type: 'presence', from: 'bob' })) // missing fields
    })

    expect(result.current.presence).toEqual({})
  })
})
