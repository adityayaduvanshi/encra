import { describe, it, expect } from 'vitest'
import { generateKeyPair, sodiumReady } from '../src/crypto/keyPair.js'
import { generateFingerprint, generateSafetyNumber } from '../src/crypto/fingerprint.js'
import { InvalidKeyError } from '../src/errors.js'

describe('generateFingerprint', () => {
  it('produces a 60-digit code in 12 groups of 5', async () => {
    await sodiumReady()
    const kp = await generateKeyPair()
    const fp = await generateFingerprint(kp.publicKey)
    expect(fp).toMatch(/^(\d{5} ){11}\d{5}$/)
  })

  it('is deterministic for the same key', async () => {
    await sodiumReady()
    const kp = await generateKeyPair()
    expect(await generateFingerprint(kp.publicKey)).toBe(await generateFingerprint(kp.publicKey))
  })

  it('throws on a wrong-length key', async () => {
    await sodiumReady()
    await expect(generateFingerprint(new Uint8Array(16))).rejects.toThrow(InvalidKeyError)
  })
})

describe('generateSafetyNumber', () => {
  it('is symmetric — both orderings yield the same code', async () => {
    await sodiumReady()
    const a = await generateKeyPair()
    const b = await generateKeyPair()
    const sn1 = await generateSafetyNumber(a.publicKey, b.publicKey)
    const sn2 = await generateSafetyNumber(b.publicKey, a.publicKey)
    expect(sn1).toBe(sn2)
    expect(sn1).toMatch(/^(\d{5} ){11}\d{5}$/)
  })

  it('differs when either key changes (MITM detection)', async () => {
    await sodiumReady()
    const a = await generateKeyPair()
    const b = await generateKeyPair()
    const c = await generateKeyPair()
    const real   = await generateSafetyNumber(a.publicKey, b.publicKey)
    const swapped = await generateSafetyNumber(a.publicKey, c.publicKey)
    expect(real).not.toBe(swapped)
  })

  it('throws on a wrong-length key', async () => {
    await sodiumReady()
    const a = await generateKeyPair()
    await expect(generateSafetyNumber(a.publicKey, new Uint8Array(8))).rejects.toThrow(InvalidKeyError)
  })
})
