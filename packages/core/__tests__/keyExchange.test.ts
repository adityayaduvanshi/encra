import { describe, it, expect } from 'vitest'
import { generateKeyPair, sodiumReady } from '../src/crypto/keyPair.js'
import { deriveSharedSecret } from '../src/crypto/keyExchange.js'
import { InvalidKeyError } from '../src/errors.js'

describe('keyExchange', () => {
  it('Alice and Bob derive the same shared secret', async () => {
    await sodiumReady()
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()

    const aliceSecret = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const bobSecret = await deriveSharedSecret(bob.privateKey, alice.publicKey)

    expect(aliceSecret).toEqual(bobSecret)
  })

  it('shared secret is 32 bytes', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    expect(secret.length).toBe(32)
  })

  it('different key pairs produce different shared secrets', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const carol = await generateKeyPair()

    const secretAB = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const secretAC = await deriveSharedSecret(alice.privateKey, carol.publicKey)

    expect(secretAB).not.toEqual(secretAC)
  })

  it('throws InvalidKeyError for wrong-length private key', async () => {
    const bob = await generateKeyPair()
    await expect(deriveSharedSecret(new Uint8Array(16), bob.publicKey)).rejects.toThrow(InvalidKeyError)
  })

  it('throws InvalidKeyError for wrong-length public key', async () => {
    const alice = await generateKeyPair()
    await expect(deriveSharedSecret(alice.privateKey, new Uint8Array(16))).rejects.toThrow(InvalidKeyError)
  })
})
