import { describe, it, expect } from 'vitest'
import { InvalidKeyError, DecryptionFailedError, KeyNotFoundError } from '../src/errors.js'
import { generateFingerprint } from '../src/crypto/fingerprint.js'
import { sodiumReady } from '../src/crypto/keyPair.js'
import { InvalidKeyError as IKE } from '../src/errors.js'

describe('typed errors', () => {
  it('InvalidKeyError has correct name and message', () => {
    const err = new InvalidKeyError('bad key')
    expect(err.name).toBe('InvalidKeyError')
    expect(err.message).toBe('bad key')
    expect(err).toBeInstanceOf(InvalidKeyError)
    expect(err).toBeInstanceOf(Error)
  })

  it('DecryptionFailedError has correct name and default message', () => {
    const err = new DecryptionFailedError()
    expect(err.name).toBe('DecryptionFailedError')
    expect(err.message).toContain('Decryption failed')
    expect(err).toBeInstanceOf(DecryptionFailedError)
    expect(err).toBeInstanceOf(Error)
  })

  it('DecryptionFailedError accepts custom message', () => {
    const err = new DecryptionFailedError('custom')
    expect(err.message).toBe('custom')
  })

  it('KeyNotFoundError has correct name and actionable message', () => {
    const err = new KeyNotFoundError('alice')
    expect(err.name).toBe('KeyNotFoundError')
    expect(err.message).toContain('alice')
    expect(err.message).toContain('registered')
    expect(err).toBeInstanceOf(KeyNotFoundError)
    expect(err).toBeInstanceOf(Error)
  })
})

describe('generateFingerprint error path', () => {
  it('throws InvalidKeyError for wrong-length public key', async () => {
    await sodiumReady()
    await expect(generateFingerprint(new Uint8Array(16))).rejects.toThrow(IKE)
  })
})
