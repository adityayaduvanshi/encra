import { describe, it, expect } from 'vitest'
import { sodiumReady } from '../src/crypto/keyPair.js'
import { encryptField, decryptField, generateFieldKey } from '../src/crypto/field.js'
import { DecryptionFailedError, InvalidKeyError } from '../src/errors.js'

describe('encryptField / decryptField / generateFieldKey', () => {
  it('round-trips a plaintext string', async () => {
    await sodiumReady()
    const key = await generateFieldKey()
    const encrypted = await encryptField('Hello, world!', key)
    const result = await decryptField(encrypted, key)
    expect(result).toBe('Hello, world!')
  })

  it('returns base64 strings (not Uint8Arrays)', async () => {
    const key = await generateFieldKey()
    const { ciphertext, nonce } = await encryptField('test', key)
    expect(typeof ciphertext).toBe('string')
    expect(typeof nonce).toBe('string')
    // URL-safe base64 — no +, /, or = padding
    expect(ciphertext).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('produces a different ciphertext on each call (random nonce)', async () => {
    const key = await generateFieldKey()
    const a = await encryptField('same value', key)
    const b = await encryptField('same value', key)
    expect(a.ciphertext).not.toBe(b.ciphertext)
    expect(a.nonce).not.toBe(b.nonce)
  })

  it('ciphertext does not contain the plaintext', async () => {
    const key = await generateFieldKey()
    const { ciphertext } = await encryptField('secret-ssn-123', key)
    expect(ciphertext).not.toContain('secret-ssn-123')
  })

  it('handles empty string', async () => {
    const key = await generateFieldKey()
    const encrypted = await encryptField('', key)
    const result = await decryptField(encrypted, key)
    expect(result).toBe('')
  })

  it('handles unicode and emoji', async () => {
    const key = await generateFieldKey()
    const encrypted = await encryptField('こんにちは 🔐 αβγ', key)
    const result = await decryptField(encrypted, key)
    expect(result).toBe('こんにちは 🔐 αβγ')
  })

  it('handles a long value (1 KB)', async () => {
    const key = await generateFieldKey()
    const long = 'x'.repeat(1024)
    const encrypted = await encryptField(long, key)
    const result = await decryptField(encrypted, key)
    expect(result).toBe(long)
  })

  it('generateFieldKey returns a 32-byte Uint8Array', async () => {
    const key = await generateFieldKey()
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
  })

  it('generates a unique key every call', async () => {
    const k1 = await generateFieldKey()
    const k2 = await generateFieldKey()
    expect(k1).not.toEqual(k2)
  })

  it('decryptField throws DecryptionFailedError with wrong key', async () => {
    const key1 = await generateFieldKey()
    const key2 = await generateFieldKey()
    const encrypted = await encryptField('secret', key1)
    await expect(decryptField(encrypted, key2)).rejects.toThrow(DecryptionFailedError)
  })

  it('decryptField throws DecryptionFailedError with tampered ciphertext', async () => {
    const key = await generateFieldKey()
    const encrypted = await encryptField('secret', key)
    // Flip the first character to corrupt the ciphertext
    const tampered = { ...encrypted, ciphertext: encrypted.ciphertext.slice(1) + 'X' }
    await expect(decryptField(tampered, key)).rejects.toThrow(DecryptionFailedError)
  })

  it('decryptField throws DecryptionFailedError with invalid base64', async () => {
    const key = await generateFieldKey()
    await expect(
      decryptField({ ciphertext: '!!!not-base64!!!', nonce: 'also-bad!!!' }, key)
    ).rejects.toThrow(DecryptionFailedError)
  })

  it('encryptField throws InvalidKeyError if key is wrong length', async () => {
    await expect(encryptField('hello', new Uint8Array(16))).rejects.toThrow(InvalidKeyError)
  })

  it('encryptField throws InvalidKeyError if value is not a string', async () => {
    const key = await generateFieldKey()
    // @ts-expect-error — intentional runtime type check
    await expect(encryptField(12345, key)).rejects.toThrow(InvalidKeyError)
  })

  it('decryptField throws InvalidKeyError if key is wrong length', async () => {
    const key = await generateFieldKey()
    const encrypted = await encryptField('hello', key)
    await expect(decryptField(encrypted, new Uint8Array(16))).rejects.toThrow(InvalidKeyError)
  })
})
