import { describe, it, expect } from 'vitest'
import _sodium from 'libsodium-wrappers'
import { sodiumReady, generateKeyPair } from '../src/crypto/keyPair.js'
import { deriveSharedSecret } from '../src/crypto/keyExchange.js'
import {
  derivePresenceKey,
  encryptPresence,
  decryptPresence,
} from '../src/crypto/presence.js'
import type { PresencePayload } from '../src/crypto/presence.js'
import { InvalidKeyError, DecryptionFailedError } from '../src/errors.js'

const SAMPLE: PresencePayload = {
  status:     'online',
  lastSeenAt: 1_700_000_000_000,
  isTyping:   false,
}

describe('derivePresenceKey', () => {
  it('derives a 32-byte key from a 32-byte shared secret', async () => {
    await sodiumReady()
    const kp     = await generateKeyPair()
    const shared = await deriveSharedSecret(kp.privateKey, kp.publicKey)
    const key    = await derivePresenceKey(shared)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
  })

  it('both parties independently derive the same key', async () => {
    await sodiumReady()
    const alice  = await generateKeyPair()
    const bob    = await generateKeyPair()
    const ab     = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const ba     = await deriveSharedSecret(bob.privateKey, alice.publicKey)
    const keyAB  = await derivePresenceKey(ab)
    const keyBA  = await derivePresenceKey(ba)
    expect(keyAB).toEqual(keyBA)
  })

  it('is different from the raw shared secret (domain separation)', async () => {
    await sodiumReady()
    const kp     = await generateKeyPair()
    const shared = await deriveSharedSecret(kp.privateKey, kp.publicKey)
    const key    = await derivePresenceKey(shared)
    expect(key).not.toEqual(shared)
  })

  it('throws InvalidKeyError if sharedSecret is not 32 bytes', async () => {
    await sodiumReady()
    await expect(derivePresenceKey(new Uint8Array(16))).rejects.toThrow(InvalidKeyError)
    await expect(derivePresenceKey(new Uint8Array(64))).rejects.toThrow(InvalidKeyError)
  })
})

describe('encryptPresence / decryptPresence', () => {
  async function makeKey(): Promise<Uint8Array> {
    await sodiumReady()
    const kp     = await generateKeyPair()
    const shared = await deriveSharedSecret(kp.privateKey, kp.publicKey)
    return derivePresenceKey(shared)
  }


  it('round-trips all presence statuses', async () => {
    const key = await makeKey()
    for (const status of ['online', 'offline', 'away', 'busy'] as const) {
      const payload: PresencePayload = { status, lastSeenAt: Date.now(), isTyping: false }
      const enc = await encryptPresence(payload, key)
      const dec = await decryptPresence(enc, key)
      expect(dec).toEqual(payload)
    }
  })

  it('round-trips isTyping true', async () => {
    const key     = await makeKey()
    const payload: PresencePayload = { status: 'online', lastSeenAt: 1_234, isTyping: true }
    const enc = await encryptPresence(payload, key)
    const dec = await decryptPresence(enc, key)
    expect(dec.isTyping).toBe(true)
  })

  it('produces base64 ciphertext and nonce', async () => {
    const key = await makeKey()
    const enc = await encryptPresence(SAMPLE, key)
    expect(typeof enc.ciphertext).toBe('string')
    expect(typeof enc.nonce).toBe('string')
    expect(enc.ciphertext).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(enc.nonce).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('produces different ciphertext on each call (random nonce)', async () => {
    const key = await makeKey()
    const a = await encryptPresence(SAMPLE, key)
    const b = await encryptPresence(SAMPLE, key)
    expect(a.ciphertext).not.toBe(b.ciphertext)
    expect(a.nonce).not.toBe(b.nonce)
  })

  it('ciphertext does not contain plaintext status', async () => {
    const key = await makeKey()
    const enc = await encryptPresence(SAMPLE, key)
    expect(enc.ciphertext).not.toContain('online')
  })

  it('throws DecryptionFailedError with wrong key', async () => {
    const key1 = await makeKey()
    const key2 = await makeKey()
    const enc  = await encryptPresence(SAMPLE, key1)
    await expect(decryptPresence(enc, key2)).rejects.toThrow(DecryptionFailedError)
  })

  it('throws DecryptionFailedError with tampered ciphertext', async () => {
    const key = await makeKey()
    const enc = await encryptPresence(SAMPLE, key)
    const tampered = { ...enc, ciphertext: enc.ciphertext.slice(1) + 'X' }
    await expect(decryptPresence(tampered, key)).rejects.toThrow(DecryptionFailedError)
  })

  it('throws DecryptionFailedError with invalid base64', async () => {
    const key = await makeKey()
    await expect(
      decryptPresence({ ciphertext: '!!!bad!!!', nonce: '!!!bad!!!' }, key)
    ).rejects.toThrow(DecryptionFailedError)
  })

  it('throws DecryptionFailedError when decrypted bytes are not valid JSON', async () => {
    await sodiumReady()
    const key   = await makeKey()
    // Encrypt a raw non-JSON string directly (valid MAC, but JSON.parse will fail)
    const nonce = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES)
    const ct    = _sodium.crypto_secretbox_easy('not-json-{{{}', nonce, key)
    const B64   = _sodium.base64_variants.URLSAFE_NO_PADDING
    const enc   = {
      ciphertext: _sodium.to_base64(new Uint8Array(ct),    B64),
      nonce:      _sodium.to_base64(new Uint8Array(nonce), B64),
    }
    await expect(decryptPresence(enc, key)).rejects.toThrow(DecryptionFailedError)
  })
})
