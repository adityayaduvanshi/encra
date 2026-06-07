import { describe, it, expect, beforeAll } from 'vitest'
import { sodiumReady } from '../src/crypto/keyPair.js'
import {
  generateIdentityKeyPair,
  sign,
  verify,
  identityPublicToX25519,
  identityPrivateToX25519,
} from '../src/crypto/identity.js'
import { InvalidKeyError } from '../src/errors.js'

beforeAll(async () => {
  await sodiumReady()
})

describe('generateIdentityKeyPair', () => {
  it('returns Ed25519 key pair of correct sizes', async () => {
    const kp = await generateIdentityKeyPair()
    expect(kp.publicKey).toBeInstanceOf(Uint8Array)
    expect(kp.privateKey).toBeInstanceOf(Uint8Array)
    expect(kp.publicKey.length).toBe(32)
    expect(kp.privateKey.length).toBe(64)
  })

  it('generates unique key pairs each call', async () => {
    const a = await generateIdentityKeyPair()
    const b = await generateIdentityKeyPair()
    expect(a.publicKey).not.toEqual(b.publicKey)
  })
})

describe('sign / verify', () => {
  it('round-trips a valid signature', async () => {
    const kp = await generateIdentityKeyPair()
    const msg = new Uint8Array([1, 2, 3, 4])
    const sig = await sign(kp.privateKey, msg)
    const ok = await verify(kp.publicKey, msg, sig)
    expect(ok).toBe(true)
  })

  it('returns false for a wrong public key', async () => {
    const kp1 = await generateIdentityKeyPair()
    const kp2 = await generateIdentityKeyPair()
    const msg = new Uint8Array([1, 2, 3])
    const sig = await sign(kp1.privateKey, msg)
    const ok = await verify(kp2.publicKey, msg, sig)
    expect(ok).toBe(false)
  })

  it('returns false for a tampered message', async () => {
    const kp = await generateIdentityKeyPair()
    const msg = new Uint8Array([1, 2, 3])
    const sig = await sign(kp.privateKey, msg)
    const tampered = new Uint8Array([9, 2, 3])
    const ok = await verify(kp.publicKey, tampered, sig)
    expect(ok).toBe(false)
  })

  it('sign throws InvalidKeyError for wrong-length private key', async () => {
    const msg = new Uint8Array([1, 2, 3])
    await expect(sign(new Uint8Array(16), msg)).rejects.toThrow(InvalidKeyError)
  })

  it('verify returns false for wrong-length signature', async () => {
    const kp = await generateIdentityKeyPair()
    const msg = new Uint8Array([1, 2, 3])
    const shortSig = new Uint8Array(16)
    const ok = await verify(kp.publicKey, msg, shortSig)
    expect(ok).toBe(false)
  })

  it('verify returns false when libsodium throws on corrupted signature', async () => {
    const kp = await generateIdentityKeyPair()
    const msg = new Uint8Array([1, 2, 3])
    const sig = await sign(kp.privateKey, msg)
    // Corrupt the signature so it's the right length but cryptographically invalid
    const corrupted = new Uint8Array(sig)
    corrupted.fill(0xff)
    const ok = await verify(kp.publicKey, msg, corrupted)
    expect(ok).toBe(false)
  })
})

describe('identityPublicToX25519', () => {
  it('converts Ed25519 public key to X25519', async () => {
    const kp = await generateIdentityKeyPair()
    const x = identityPublicToX25519(kp.publicKey)
    expect(x).toBeInstanceOf(Uint8Array)
    expect(x.length).toBe(32)
  })

  it('throws InvalidKeyError for wrong-length input', () => {
    expect(() => identityPublicToX25519(new Uint8Array(16))).toThrow(InvalidKeyError)
  })
})

describe('identityPrivateToX25519', () => {
  it('converts Ed25519 private key to X25519', async () => {
    const kp = await generateIdentityKeyPair()
    const x = identityPrivateToX25519(kp.privateKey)
    expect(x).toBeInstanceOf(Uint8Array)
    expect(x.length).toBe(32)
  })

  it('throws InvalidKeyError for wrong-length input', () => {
    expect(() => identityPrivateToX25519(new Uint8Array(16))).toThrow(InvalidKeyError)
  })
})
