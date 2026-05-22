import { describe, it, expect } from 'vitest'
import { generateKeyPair, exportKey, importKey, sodiumReady } from '../src/crypto/keyPair.js'
import { InvalidKeyError } from '../src/errors.js'

describe('keyPair', () => {
  it('generates a key pair with correct lengths', async () => {
    await sodiumReady()
    const kp = await generateKeyPair()
    expect(kp.publicKey).toBeInstanceOf(Uint8Array)
    expect(kp.privateKey).toBeInstanceOf(Uint8Array)
    expect(kp.publicKey.length).toBe(32)
    expect(kp.privateKey.length).toBe(32)
  })

  it('generates unique key pairs each call', async () => {
    const a = await generateKeyPair()
    const b = await generateKeyPair()
    expect(a.publicKey).not.toEqual(b.publicKey)
    expect(a.privateKey).not.toEqual(b.privateKey)
  })

  it('round-trips exportKey → importKey', async () => {
    const kp = await generateKeyPair()
    const b64 = exportKey(kp.publicKey)
    const restored = importKey(b64)
    expect(restored).toEqual(kp.publicKey)
  })

  it('exportKey returns a non-empty string', async () => {
    const kp = await generateKeyPair()
    const b64 = exportKey(kp.publicKey)
    expect(typeof b64).toBe('string')
    expect(b64.length).toBeGreaterThan(0)
  })

  it('exportKey throws InvalidKeyError on empty key', () => {
    expect(() => exportKey(new Uint8Array(0))).toThrow(InvalidKeyError)
  })

  it('importKey throws InvalidKeyError on empty string', () => {
    expect(() => importKey('')).toThrow(InvalidKeyError)
  })

  it('importKey throws InvalidKeyError on invalid base64', () => {
    expect(() => importKey('!!!not-base64!!!')).toThrow(InvalidKeyError)
  })
})
