import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useE2EForm } from '../src/useE2EForm.js'
import * as ratchetStore from '../src/ratchetStore.js'
import * as core from '@encra/core'
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

describe('useE2EForm', () => {
  const keyStore = new Map<string, string>()

  beforeAll(async () => { await sodiumReady() })

  afterEach(() => {
    keyStore.clear()
    vi.restoreAllMocks()
  })

  function setup(userId: string) {
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    return renderHook(() =>
      useE2EForm({ apiKey: 'test-key', userId, serverUrl: 'http://localhost:3000' })
    )
  }

  it('becomes ready after key registration', async () => {
    const { result } = setup('form-alice')
    await waitFor(() => expect(result.current.isReady).toBe(true))
    expect(result.current.error).toBeNull()
  })

  it('encrypt → decrypt round-trips all field values', async () => {
    // Mock deriveSharedSecret to return a native Uint8Array (avoids WASM cross-realm
    // issues in jsdom's inlined module environment — same pattern as useE2EChat tests).
    const sharedKey = new Uint8Array(32).fill(0x42)
    vi.spyOn(core, 'deriveSharedSecret').mockResolvedValue(sharedKey)

    const aliceHook = setup('form-alice2')
    await waitFor(() => expect(aliceHook.result.current.isReady).toBe(true))

    const bobKP = await generateKeyPair()
    keyStore.set('form-bob', exportKey(bobKP.publicKey))

    vi.spyOn(ratchetStore, 'loadKeyPair').mockImplementation(async (uid) => {
      if (uid === 'form-bob') return { pub: exportKey(bobKP.publicKey), priv: exportKey(bobKP.privateKey) }
      return null
    })

    const bobHook = renderHook(() =>
      useE2EForm({ apiKey: 'test-key', userId: 'form-bob', serverUrl: 'http://localhost:3000' })
    )
    await waitFor(() => expect(bobHook.result.current.isReady).toBe(true))

    const fields = { name: 'Alice Smith', ssn: '123-45-6789', notes: 'Private notes 🔐' }

    let encrypted: Awaited<ReturnType<typeof aliceHook.result.current.encryptFields>>
    await act(async () => {
      encrypted = await aliceHook.result.current.encryptFields(fields, 'form-bob')
    })

    // Same keys, values replaced by { ciphertext, nonce }
    expect(Object.keys(encrypted!)).toEqual(['name', 'ssn', 'notes'])
    for (const key of Object.keys(fields) as (keyof typeof fields)[]) {
      expect(encrypted![key]).toHaveProperty('ciphertext')
      expect(encrypted![key]).toHaveProperty('nonce')
      expect(typeof encrypted![key]!.ciphertext).toBe('string')
      // Ciphertext is base64, should not contain the plaintext
      expect(encrypted![key]!.ciphertext).not.toContain(fields[key])
    }

    // Each field gets a unique nonce
    const nonces = Object.values(encrypted!).map((v) => v.nonce)
    expect(new Set(nonces).size).toBe(nonces.length)

    // Decrypt with the same mocked shared key — both sides use the same sharedKey
    let decrypted: Record<string, string>
    await act(async () => {
      decrypted = await bobHook.result.current.decryptFields(encrypted!, 'form-alice2')
    })

    expect(decrypted!).toEqual(fields)
  })

  it('encrypts empty fields object', async () => {
    const { result } = setup('form-empty')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const peerKP = await generateKeyPair()
    keyStore.set('form-empty-peer', exportKey(peerKP.publicKey))

    let encrypted: Awaited<ReturnType<typeof result.current.encryptFields>>
    await act(async () => {
      encrypted = await result.current.encryptFields({}, 'form-empty-peer')
    })
    expect(encrypted!).toEqual({})
  })

  it('produces unique ciphertexts on repeated calls (fresh nonce per call)', async () => {
    vi.spyOn(core, 'deriveSharedSecret').mockResolvedValue(new Uint8Array(32).fill(0x11))

    const { result } = setup('form-nonce')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const peerKP = await generateKeyPair()
    keyStore.set('form-nonce-peer', exportKey(peerKP.publicKey))

    let enc1: Awaited<ReturnType<typeof result.current.encryptFields>>
    let enc2: Awaited<ReturnType<typeof result.current.encryptFields>>

    await act(async () => {
      enc1 = await result.current.encryptFields({ secret: 'same value' }, 'form-nonce-peer')
      enc2 = await result.current.encryptFields({ secret: 'same value' }, 'form-nonce-peer')
    })

    expect(enc1!.secret!.ciphertext).not.toBe(enc2!.secret!.ciphertext)
    expect(enc1!.secret!.nonce).not.toBe(enc2!.secret!.nonce)
  })

  it('decryptFields throws on tampered ciphertext', async () => {
    vi.spyOn(core, 'deriveSharedSecret').mockResolvedValue(new Uint8Array(32).fill(0x22))

    const { result } = setup('form-tamper')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const peerKP = await generateKeyPair()
    keyStore.set('form-tamper-peer', exportKey(peerKP.publicKey))

    let encrypted: Awaited<ReturnType<typeof result.current.encryptFields>>
    await act(async () => {
      encrypted = await result.current.encryptFields({ secret: 'test' }, 'form-tamper-peer')
    })

    // Tamper: flip first character of ciphertext
    const tampered = {
      ...encrypted!,
      secret: { ...encrypted!.secret!, ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    }
    await expect(result.current.decryptFields(tampered, 'form-tamper-peer')).rejects.toThrow()
  })

  it('throws if encryptFields called before isReady', async () => {
    vi.stubGlobal('fetch', makeFetchMock(keyStore))
    const { result } = renderHook(() =>
      useE2EForm({ apiKey: 'test-key', userId: 'form-notready', serverUrl: 'http://localhost:3000' })
    )
    await expect(result.current.encryptFields({ x: 'y' }, 'other')).rejects.toThrow('not ready')
  })

  it('throws when recipient key not found (404)', async () => {
    const { result } = setup('form-404')
    await waitFor(() => expect(result.current.isReady).toBe(true))
    await expect(result.current.encryptFields({ x: 'y' }, 'ghost')).rejects.toThrow(
      "Could not fetch public key for 'ghost'"
    )
  })

  it('throws if a field value is not a string', async () => {
    vi.spyOn(core, 'deriveSharedSecret').mockResolvedValue(new Uint8Array(32).fill(0x33))

    const { result } = setup('form-typecheck')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const peerKP = await generateKeyPair()
    keyStore.set('form-typecheck-peer', exportKey(peerKP.publicKey))

    await expect(
      // @ts-expect-error — intentional runtime type check
      result.current.encryptFields({ age: 42 }, 'form-typecheck-peer')
    ).rejects.toThrow('must be a string')
  })

  it('caches peer public keys (only fetches once)', async () => {
    vi.spyOn(core, 'deriveSharedSecret').mockResolvedValue(new Uint8Array(32).fill(0x44))

    const { result } = setup('form-cache')
    await waitFor(() => expect(result.current.isReady).toBe(true))

    const peerKP = await generateKeyPair()
    keyStore.set('form-cache-peer', exportKey(peerKP.publicKey))

    const fetchMock = vi.mocked(globalThis.fetch as ReturnType<typeof vi.fn>)

    await act(async () => {
      await result.current.encryptFields({ a: '1' }, 'form-cache-peer')
      await result.current.encryptFields({ b: '2' }, 'form-cache-peer')
    })

    const keyFetches = fetchMock.mock.calls.filter(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/v1/keys/form-cache-peer')
    )
    expect(keyFetches.length).toBe(1)
  })

  it('sets fatal error if key registration fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) } as Response)))
    const onError = vi.fn()
    const { result } = renderHook(() =>
      useE2EForm({ apiKey: 'bad', userId: 'form-fail', serverUrl: 'http://localhost:3000', onError })
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
      useE2EForm({ apiKey: 'test-key', userId: 'form-restore', serverUrl: 'http://localhost:3000' })
    )
    await waitFor(() => expect(result.current.isReady).toBe(true))
    expect(saveSpy).not.toHaveBeenCalled()
  })
})
