import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useE2EFile, MAX_FILE_BYTES } from '../src/useE2EFile.js'
import * as ratchetStore from '../src/ratchetStore.js'
import { sodiumReady, generateKeyPair, exportKey } from '@encra/core'

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

describe('useE2EFile', () => {
  const keyStore = new Map<string, string>()

  beforeAll(async () => { await sodiumReady() })

  afterEach(() => {
    keyStore.clear()
    vi.restoreAllMocks()
  })

  function setup(userId: string) {
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    return renderHook(() =>
      useE2EFile({ apiKey: 'test-key', userId, serverUrl: 'http://localhost:3000' })
    )
  }

  it('becomes ready after key registration', async () => {
    const { result } = setup('file-alice')
    await waitFor(() => expect(result.current.isReady).toBe(true))
    expect(result.current.error).toBeNull()
  })

  it('encrypt → decrypt round-trips a text file', async () => {
    const aliceHook = setup('fa-alice')
    await waitFor(() => expect(aliceHook.result.current.isReady).toBe(true))

    // Register Bob's key pair so Alice can fetch it
    const bobKP = await generateKeyPair()
    keyStore.set('fa-bob', exportKey(bobKP.publicKey))

    // Stub Bob's key pair into IDB so his hook loads it
    vi.spyOn(ratchetStore, 'loadKeyPair').mockImplementation(async (uid) => {
      if (uid === 'fa-bob') return { pub: exportKey(bobKP.publicKey), priv: exportKey(bobKP.privateKey) }
      return null
    })

    const bobHook = renderHook(() =>
      useE2EFile({ apiKey: 'test-key', userId: 'fa-bob', serverUrl: 'http://localhost:3000' })
    )
    await waitFor(() => expect(bobHook.result.current.isReady).toBe(true))

    const file = new File(['Hello from useE2EFile!'], 'hello.txt', { type: 'text/plain' })

    let encrypted: Awaited<ReturnType<typeof aliceHook.result.current.encryptFile>>
    await act(async () => {
      encrypted = await aliceHook.result.current.encryptFile(file, 'fa-bob')
    })

    expect(encrypted!.name).toBe('hello.txt')
    expect(encrypted!.mimeType).toBe('text/plain')
    expect(encrypted!.size).toBe(file.size)
    expect(encrypted!.ciphertext).toBeInstanceOf(Uint8Array)
    expect(encrypted!.nonce).toBeInstanceOf(Uint8Array)

    // Ciphertext should not contain the plaintext
    const ctStr = Buffer.from(encrypted!.ciphertext).toString('utf8')
    expect(ctStr).not.toContain('Hello from useE2EFile!')

    let decrypted: File
    await act(async () => {
      // Bob needs Alice's public key in the keyStore so he can fetch it
      const aliceKP = await ratchetStore.loadKeyPair('fa-alice')
      if (aliceKP) keyStore.set('fa-alice', aliceKP.pub)
      decrypted = await bobHook.result.current.decryptFile(encrypted!, 'fa-alice')
    })

    // jsdom doesn't implement File.text() — use FileReader instead
    const text = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader()
      reader.onload  = () => resolve(reader.result as string)
      reader.onerror = () => reject(reader.error)
      reader.readAsText(decrypted!)
    })
    expect(text).toBe('Hello from useE2EFile!')
    expect(decrypted!.name).toBe('hello.txt')
    expect(decrypted!.type).toBe('text/plain')
  })

  it('encrypts a Blob (no filename)', async () => {
    const { result } = setup('fa-blob-user')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const bobKP = await generateKeyPair()
    keyStore.set('fa-blob-peer', exportKey(bobKP.publicKey))

    const blob = new Blob(['binary data'], { type: 'application/octet-stream' })

    let encrypted: Awaited<ReturnType<typeof result.current.encryptFile>>
    await act(async () => {
      encrypted = await result.current.encryptFile(blob, 'fa-blob-peer')
    })

    expect(encrypted!.name).toBe('file')          // default name for Blob
    expect(encrypted!.mimeType).toBe('application/octet-stream')
  })

  it('throws if encryptFile called before isReady', async () => {
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    // Don't wait for ready
    const { result } = renderHook(() =>
      useE2EFile({ apiKey: 'test-key', userId: 'fa-notready', serverUrl: 'http://localhost:3000' })
    )
    const file = new File(['x'], 'x.txt')
    await expect(result.current.encryptFile(file, 'other')).rejects.toThrow('not ready')
  })

  it('throws if file exceeds MAX_FILE_BYTES', async () => {
    const { result } = setup('fa-toobig')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const bigFile = { size: MAX_FILE_BYTES + 1, type: 'text/plain', arrayBuffer: vi.fn() } as unknown as File
    await expect(result.current.encryptFile(bigFile, 'anyone')).rejects.toThrow('too large')
  })

  it('throws when recipient key is not found (404)', async () => {
    const { result } = setup('fa-unknown-peer')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const file = new File(['data'], 'f.txt')
    // 'ghost' is not in keyStore → 404
    await expect(result.current.encryptFile(file, 'ghost')).rejects.toThrow("Could not fetch public key for 'ghost'")
  })

  it('caches peer public keys (only fetches once)', async () => {
    const { result } = setup('fa-cache')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const peerKP = await generateKeyPair()
    keyStore.set('fa-cache-peer', exportKey(peerKP.publicKey))

    const fetchMock = vi.mocked(globalThis.fetch as ReturnType<typeof vi.fn>)
    const file = new File(['a'], 'a.txt')

    await act(async () => { await result.current.encryptFile(file, 'fa-cache-peer') })
    await act(async () => { await result.current.encryptFile(file, 'fa-cache-peer') })

    const keyFetches = fetchMock.mock.calls.filter(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/v1/keys/fa-cache-peer')
    )
    expect(keyFetches.length).toBe(1)  // fetched only once
  })

  it('sets fatal error if key registration fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) } as Response)))
    const onError = vi.fn()
    const { result } = renderHook(() =>
      useE2EFile({ apiKey: 'bad-key', userId: 'fa-fail', serverUrl: 'http://localhost:3000', onError })
    )
    await waitFor(() => expect(result.current.error).not.toBeNull())
    expect(result.current.isReady).toBe(false)
    expect(onError).toHaveBeenCalled()
  })

  it('restores key pair from IDB without generating a new one', async () => {
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    const storedKP = await generateKeyPair()
    vi.spyOn(ratchetStore, 'loadKeyPair').mockResolvedValue({
      pub:  exportKey(storedKP.publicKey),
      priv: exportKey(storedKP.privateKey),
    })
    const saveSpy = vi.spyOn(ratchetStore, 'saveKeyPair').mockResolvedValue()

    const { result } = renderHook(() =>
      useE2EFile({ apiKey: 'test-key', userId: 'fa-restore', serverUrl: 'http://localhost:3000' })
    )
    await waitFor(() => expect(result.current.isReady).toBe(true))
    expect(saveSpy).not.toHaveBeenCalled()
  })
})
