import { describe, it, expect } from 'vitest'
import { generateKeyPair, sodiumReady } from '../src/crypto/keyPair.js'
import { deriveSharedSecret } from '../src/crypto/keyExchange.js'
import { encrypt, decrypt } from '../src/crypto/encrypt.js'
import { DecryptionFailedError, InvalidKeyError } from '../src/errors.js'

describe('encrypt / decrypt', () => {
  it('round-trips plaintext through encrypt→decrypt', async () => {
    await sodiumReady()
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey)

    const { ciphertext, nonce } = await encrypt('Hello Bob!', secret)
    const result = await decrypt(ciphertext, nonce, secret)

    expect(result).toBe('Hello Bob!')
  })

  it('ciphertext is not equal to plaintext bytes', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const { ciphertext } = await encrypt('Secret message', secret)

    const encoder = new TextEncoder()
    expect(ciphertext).not.toEqual(encoder.encode('Secret message'))
  })

  it('produces a unique nonce every call', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey)

    const { nonce: n1 } = await encrypt('msg', secret)
    const { nonce: n2 } = await encrypt('msg', secret)

    expect(n1).not.toEqual(n2)
  })

  it('decrypt throws DecryptionFailedError with wrong key', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const carol = await generateKeyPair()

    const correctSecret = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const wrongSecret = await deriveSharedSecret(alice.privateKey, carol.publicKey)

    const { ciphertext, nonce } = await encrypt('Hello', correctSecret)
    await expect(decrypt(ciphertext, nonce, wrongSecret)).rejects.toThrow(DecryptionFailedError)
  })

  it('decrypt throws DecryptionFailedError with tampered ciphertext', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const { ciphertext, nonce } = await encrypt('Hello', secret)

    ciphertext[0] ^= 0xff
    await expect(decrypt(ciphertext, nonce, secret)).rejects.toThrow(DecryptionFailedError)
  })

  it('encrypt throws InvalidKeyError for wrong-length key', async () => {
    await expect(encrypt('Hello', new Uint8Array(16))).rejects.toThrow(InvalidKeyError)
  })

  it('decrypt throws InvalidKeyError for wrong-length key', async () => {
    await expect(decrypt(new Uint8Array(48), new Uint8Array(24), new Uint8Array(16))).rejects.toThrow(
      InvalidKeyError
    )
  })

  it('handles empty string plaintext', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const { ciphertext, nonce } = await encrypt('', secret)
    const result = await decrypt(ciphertext, nonce, secret)
    expect(result).toBe('')
  })

  it('handles unicode plaintext', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const { ciphertext, nonce } = await encrypt('こんにちは 🔐', secret)
    const result = await decrypt(ciphertext, nonce, secret)
    expect(result).toBe('こんにちは 🔐')
  })
})
