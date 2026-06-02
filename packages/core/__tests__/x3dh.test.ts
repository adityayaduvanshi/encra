import { describe, it, expect } from 'vitest'
import { sodiumReady } from '../src/crypto/keyPair.js'
import {
  generateIdentityKeyPair,
  sign,
  verify,
  identityPublicToX25519,
  identityPrivateToX25519,
} from '../src/crypto/identity.js'
import {
  generateSignedPreKey,
  generateOneTimePreKeys,
  buildPreKeyBundle,
  x3dhInitiate,
  x3dhRespond,
} from '../src/crypto/x3dh.js'
import { DoubleRatchet } from '../src/crypto/ratchet.js'
import { deriveSharedSecret } from '../src/crypto/keyExchange.js'
import { InvalidKeyError, DecryptionFailedError } from '../src/errors.js'

describe('identity keys', () => {
  it('generates Ed25519 key pairs of the right size', async () => {
    await sodiumReady()
    const id = await generateIdentityKeyPair()
    expect(id.publicKey.length).toBe(32)
    expect(id.privateKey.length).toBe(64)
  })

  it('signs and verifies a message', async () => {
    const id = await generateIdentityKeyPair()
    const msg = new Uint8Array([1, 2, 3, 4, 5])
    const sig = await sign(id.privateKey, msg)
    expect(sig.length).toBe(64)
    expect(await verify(id.publicKey, msg, sig)).toBe(true)
  })

  it('rejects a tampered message', async () => {
    const id = await generateIdentityKeyPair()
    const msg = new Uint8Array([1, 2, 3])
    const sig = await sign(id.privateKey, msg)
    expect(await verify(id.publicKey, new Uint8Array([1, 2, 4]), sig)).toBe(false)
  })

  it('rejects a signature from a different key', async () => {
    const a = await generateIdentityKeyPair()
    const b = await generateIdentityKeyPair()
    const msg = new Uint8Array([9, 9, 9])
    const sig = await sign(a.privateKey, msg)
    expect(await verify(b.publicKey, msg, sig)).toBe(false)
  })

  it('returns false for a wrong-length signature instead of throwing', async () => {
    const id = await generateIdentityKeyPair()
    expect(await verify(id.publicKey, new Uint8Array([1]), new Uint8Array(10))).toBe(false)
  })

  it('throws InvalidKeyError on malformed identity public key', async () => {
    await expect(verify(new Uint8Array(10), new Uint8Array([1]), new Uint8Array(64))).rejects.toThrow(
      InvalidKeyError
    )
  })

  it('Ed25519→X25519 conversion agrees between public and private halves', async () => {
    const id = await generateIdentityKeyPair()
    const xPriv = identityPrivateToX25519(id.privateKey)
    const xPub = identityPublicToX25519(id.publicKey)
    // The converted public key must equal scalarmult_base(converted private key)
    const other = await generateIdentityKeyPair()
    const otherXPriv = identityPrivateToX25519(other.privateKey)
    const otherXPub = identityPublicToX25519(other.publicKey)
    // DH agreement across the converted keys
    const s1 = await deriveSharedSecret(xPriv, otherXPub)
    const s2 = await deriveSharedSecret(otherXPriv, xPub)
    expect(s1).toEqual(s2)
  })
})

describe('prekey generation', () => {
  it('signed prekey carries a valid identity signature', async () => {
    const id = await generateIdentityKeyPair()
    const spk = await generateSignedPreKey(id, 1)
    expect(spk.keyId).toBe(1)
    expect(spk.keyPair.publicKey.length).toBe(32)
    expect(await verify(id.publicKey, spk.keyPair.publicKey, spk.signature)).toBe(true)
  })

  it('generates a batch of one-time prekeys with sequential ids', async () => {
    const otps = await generateOneTimePreKeys(5, 10)
    expect(otps).toHaveLength(10)
    expect(otps[0]!.keyId).toBe(5)
    expect(otps[9]!.keyId).toBe(14)
    // all unique
    const pubs = new Set(otps.map((o) => o.keyPair.publicKey.join(',')))
    expect(pubs.size).toBe(10)
  })

  it('builds a bundle with and without a one-time prekey', async () => {
    const id = await generateIdentityKeyPair()
    const spk = await generateSignedPreKey(id, 1)
    const [otp] = await generateOneTimePreKeys(1, 1)

    const withOtp = buildPreKeyBundle(id, spk, otp)
    expect(withOtp.oneTimePreKey).toBeDefined()
    expect(withOtp.oneTimePreKey!.keyId).toBe(1)

    const withoutOtp = buildPreKeyBundle(id, spk)
    expect(withoutOtp.oneTimePreKey).toBeUndefined()
  })
})

describe('X3DH handshake', () => {
  async function setupBob() {
    const identity = await generateIdentityKeyPair()
    const signedPreKey = await generateSignedPreKey(identity, 1)
    const [oneTimePreKey] = await generateOneTimePreKeys(1, 1)
    return { identity, signedPreKey, oneTimePreKey }
  }

  it('initiator and responder derive the same shared secret (with OTP)', async () => {
    const alice = await generateIdentityKeyPair()
    const bob = await setupBob()
    const bundle = buildPreKeyBundle(bob.identity, bob.signedPreKey, bob.oneTimePreKey)

    const init = await x3dhInitiate(alice, bundle)
    const bobSecret = await x3dhRespond(
      bob.identity,
      bob.signedPreKey.keyPair,
      bob.oneTimePreKey!.keyPair,
      init.message
    )

    expect(init.sharedSecret.length).toBe(32)
    expect(init.sharedSecret).toEqual(bobSecret)
    expect(init.message.oneTimePreKeyId).toBe(1)
  })

  it('works without a one-time prekey (3-DH variant)', async () => {
    const alice = await generateIdentityKeyPair()
    const bob = await setupBob()
    const bundle = buildPreKeyBundle(bob.identity, bob.signedPreKey) // no OTP

    const init = await x3dhInitiate(alice, bundle)
    const bobSecret = await x3dhRespond(bob.identity, bob.signedPreKey.keyPair, null, init.message)

    expect(init.message.oneTimePreKeyId).toBeNull()
    expect(init.sharedSecret).toEqual(bobSecret)
  })

  it('exposes the signed-prekey public key for ratchet seeding', async () => {
    const alice = await generateIdentityKeyPair()
    const bob = await setupBob()
    const bundle = buildPreKeyBundle(bob.identity, bob.signedPreKey, bob.oneTimePreKey)
    const init = await x3dhInitiate(alice, bundle)
    expect(init.signedPreKeyPublic).toEqual(bob.signedPreKey.keyPair.publicKey)
  })

  it('rejects a bundle whose signed prekey signature is invalid (MITM guard)', async () => {
    const alice = await generateIdentityKeyPair()
    const bob = await setupBob()
    const bundle = buildPreKeyBundle(bob.identity, bob.signedPreKey, bob.oneTimePreKey)

    // Tamper: swap in a different identity key so the signature no longer matches.
    const attacker = await generateIdentityKeyPair()
    const { exportKey } = await import('../src/crypto/keyPair.js')
    bundle.identityKey = exportKey(attacker.publicKey)

    await expect(x3dhInitiate(alice, bundle)).rejects.toThrow(InvalidKeyError)
  })

  it('responder throws if an OTP id is referenced but no key supplied', async () => {
    const alice = await generateIdentityKeyPair()
    const bob = await setupBob()
    const bundle = buildPreKeyBundle(bob.identity, bob.signedPreKey, bob.oneTimePreKey)
    const init = await x3dhInitiate(alice, bundle)

    await expect(
      x3dhRespond(bob.identity, bob.signedPreKey.keyPair, null, init.message)
    ).rejects.toThrow(DecryptionFailedError)
  })

  it('different initiators derive different secrets with the same bundle', async () => {
    const aliceA = await generateIdentityKeyPair()
    const aliceB = await generateIdentityKeyPair()
    const bob = await setupBob()
    const bundle = buildPreKeyBundle(bob.identity, bob.signedPreKey)

    const initA = await x3dhInitiate(aliceA, bundle)
    const initB = await x3dhInitiate(aliceB, bundle)
    expect(initA.sharedSecret).not.toEqual(initB.sharedSecret)
  })

  it('end-to-end: X3DH secret seeds a working Double Ratchet session', async () => {
    const alice = await generateIdentityKeyPair()
    const bob = await setupBob()
    const bundle = buildPreKeyBundle(bob.identity, bob.signedPreKey, bob.oneTimePreKey)

    // Alice initiates and seeds her sending ratchet with Bob's signed prekey.
    const init = await x3dhInitiate(alice, bundle)
    const aliceRatchet = await DoubleRatchet.initSender(init.sharedSecret, init.signedPreKeyPublic)

    // Bob derives the same secret and seeds his receiving ratchet with his SPK pair.
    const bobSecret = await x3dhRespond(
      bob.identity,
      bob.signedPreKey.keyPair,
      bob.oneTimePreKey!.keyPair,
      init.message
    )
    const bobRatchet = await DoubleRatchet.initReceiver(bobSecret, bob.signedPreKey.keyPair)

    const msg1 = await aliceRatchet.encrypt('hello bob')
    expect(await bobRatchet.decrypt(msg1)).toBe('hello bob')

    const reply = await bobRatchet.encrypt('hi alice')
    expect(await aliceRatchet.decrypt(reply)).toBe('hi alice')

    const msg2 = await aliceRatchet.encrypt('how are you?')
    expect(await bobRatchet.decrypt(msg2)).toBe('how are you?')
  })
})
