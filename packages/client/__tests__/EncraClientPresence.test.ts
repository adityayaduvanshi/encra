import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { EncraClient } from '../src/EncraClient.js'
import * as ratchetStore from '../src/ratchetStore.js'
import {
  sodiumReady,
  generateKeyPair,
  exportKey,
  generateIdentityKeyPair,
  generateSignedPreKey,
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
  presenceSends() {
    return this.sentMessages.map((m) => JSON.parse(m) as Record<string, unknown>)
      .filter((m) => m['type'] === 'presence')
  }
}

// ── fetch mock: /v1/keys + non-consuming /v1/prekeys ────────────────────────────

const TEST_DEVICE_ID = 'test-device'

function makeFetchMock(keyStore: Map<string, string>, bundleStore: Map<string, PreKeyBundle>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    const ok  = (body: unknown, status = 200) => ({ ok: true, status, json: async () => body } as Response)
    const nf  = () => ({ ok: false, status: 404, json: async () => ({}) } as Response)

    if (url.endsWith('/v1/keys') && init?.method === 'POST') {
      const b = JSON.parse(init.body as string) as { userId: string; publicKey: string; deviceId?: string }
      keyStore.set(b.userId, b.publicKey)
      return ok({ userId: b.userId, deviceId: b.deviceId ?? TEST_DEVICE_ID }, 201)
    }
    if (url.endsWith('/v1/prekeys') && init?.method === 'POST') {
      const b = JSON.parse(init.body as string) as {
        userId: string; deviceId: string; identityKey: string
        signedPreKey: { keyId: number; publicKey: string; signature: string }
      }
      bundleStore.set(`${b.userId}:${b.deviceId}`, { identityKey: b.identityKey, signedPreKey: b.signedPreKey })
      return ok({ userId: b.userId, deviceId: b.deviceId, oneTimePreKeyCount: 0 }, 201)
    }
    const pk = url.match(/\/v1\/prekeys\/([^/?]+)\/([^/?]+)/)
    if (pk) {
      const entry = bundleStore.get(`${decodeURIComponent(pk[1]!)}:${decodeURIComponent(pk[2]!)}`)
      return entry ? ok(entry) : nf()
    }
    const km = url.match(/\/v1\/keys\/([^/?]+)$/)
    if (km) {
      const uid = decodeURIComponent(km[1]!)
      const key = keyStore.get(uid)
      return key ? ok({ userId: uid, devices: [{ deviceId: TEST_DEVICE_ID, publicKey: key }] }) : nf()
    }
    return nf()
  })
}

interface Peer { identity: IdentityKeyPair; signedPair: KeyPair; bundle: PreKeyBundle }

async function makePeer(): Promise<Peer> {
  const identity = await generateIdentityKeyPair()
  const spk      = await generateSignedPreKey(identity, 1)
  return { identity, signedPair: spk.keyPair, bundle: buildPreKeyBundle(identity, spk) }
}

function onceReady(client: EncraClient): Promise<void> {
  return new Promise((resolve) => {
    if (client.isReady) return resolve()
    client.on('ready', () => resolve())
  })
}

describe('EncraClient presence', () => {
  const keyStore    = new Map<string, string>()
  const bundleStore = new Map<string, PreKeyBundle>()
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
    vi.spyOn(ratchetStore, 'loadGhostMode').mockResolvedValue(false)
    vi.spyOn(ratchetStore, 'saveGhostMode').mockResolvedValue()
    vi.stubGlobal('WebSocket', class extends MockWebSocket {
      constructor(url: string) { super(url); mockWs = this }
    })
  }

  async function publishPeer(userId: string, peer: Peer) {
    const kp = await generateKeyPair()
    keyStore.set(userId, exportKey(kp.publicKey))
    bundleStore.set(`${userId}:${TEST_DEVICE_ID}`, peer.bundle)
  }

  it('sendPresence broadcasts an encrypted, decryptable status', async () => {
    setupMocks()
    const carol = await makePeer()
    await publishPeer('carol', carol)

    const client = new EncraClient({ apiKey: 'k', userId: 'alice', serverUrl: 'http://localhost:3000' })
    await client.connect()
    await onceReady(client)

    await client.sendPresence('carol', { status: 'online', lastSeenAt: 42, isTyping: false })

    const frame = mockWs.presenceSends().find((m) => m['to'] === 'carol')!
    expect(frame).toBeTruthy()
    expect(frame['prekey']).toBeTruthy()

    const keys = await x3dhRespond(carol.identity, carol.signedPair, null, frame['prekey'] as PreKeyMessage)
    const pKey = await derivePresenceKey(keys.rootKey)
    const payload = await decryptPresence(
      { ciphertext: frame['ciphertext'] as string, nonce: frame['nonce'] as string }, pKey,
    )
    expect(payload.status).toBe('online')
    expect(payload.lastSeenAt).toBe(42)

    client.disconnect()
  })

  it('emits a presence event for an encrypted inbound update', async () => {
    setupMocks()
    const client = new EncraClient({ apiKey: 'k', userId: 'alice', serverUrl: 'http://localhost:3000' })

    const events: Array<{ from: string; payload: { status: string; isTyping: boolean } }> = []
    client.on('presence', (e) => events.push(e as never))

    await client.connect()
    await onceReady(client)

    const aliceBundle = bundleStore.get(`alice:${TEST_DEVICE_ID}`)!
    const bobIdentity = await generateIdentityKeyPair()
    const init = await x3dhInitiate(bobIdentity, aliceBundle)
    const pKey = await derivePresenceKey(init.sessionKeys.rootKey)
    const enc  = await encryptPresence({ status: 'busy', lastSeenAt: 7, isTyping: true }, pKey)

    mockWs.simulateMessage(JSON.stringify({
      type: 'presence', from: 'bob', fromDeviceId: 'bob-dev',
      ciphertext: enc.ciphertext, nonce: enc.nonce, prekey: init.message,
    }))

    await vi.waitFor(() => expect(events.length).toBe(1))
    expect(events[0]!.from).toBe('bob')
    expect(events[0]!.payload.status).toBe('busy')
    expect(events[0]!.payload.isTyping).toBe(true)

    client.disconnect()
  })

  it('ghost mode suppresses sendPresence and persists the flag', async () => {
    setupMocks()
    const carol = await makePeer()
    await publishPeer('carol', carol)

    const client = new EncraClient({ apiKey: 'k', userId: 'alice', serverUrl: 'http://localhost:3000' })
    await client.connect()
    await onceReady(client)

    await client.setGhostMode(true)
    expect(client.ghostMode).toBe(true)
    expect(ratchetStore.saveGhostMode).toHaveBeenCalledWith('alice', true)

    const before = mockWs.presenceSends().length
    await client.sendPresence('carol', { status: 'online', lastSeenAt: 1, isTyping: false })
    expect(mockWs.presenceSends().length).toBe(before) // suppressed

    client.disconnect()
  })
})
