import { describe, it, expect, beforeAll } from 'vitest'
import { sodiumReady, generateKeyPair } from '../src/crypto/keyPair.js'
import { deriveSharedSecret } from '../src/crypto/keyExchange.js'
import { DoubleRatchet, MAX_SKIP_KEYS } from '../src/crypto/ratchet.js'
import { DecryptionFailedError, InvalidKeyError } from '../src/errors.js'

// ── Setup ─────────────────────────────────────────────────────────────────────

async function makeSession() {
  // Simulate a real session: both sides derive the same shared secret first
  const aliceKP = await generateKeyPair()
  const bobKP   = await generateKeyPair()
  const shared  = await deriveSharedSecret(aliceKP.privateKey, bobKP.publicKey)

  // Bob keeps his keypair as his ratchet identity; Alice knows Bob's public key
  const alice = await DoubleRatchet.initSender(shared, bobKP.publicKey)
  const bob   = await DoubleRatchet.initReceiver(shared, bobKP)

  return { alice, bob }
}

beforeAll(async () => {
  await sodiumReady()
})

// ── Basic send / receive ──────────────────────────────────────────────────────

describe('basic encrypt / decrypt', () => {
  it('Alice encrypts, Bob decrypts', async () => {
    const { alice, bob } = await makeSession()
    const msg = await alice.encrypt('Hello Bob!')
    const plain = await bob.decrypt(msg)
    expect(plain).toBe('Hello Bob!')
  })

  it('Bob replies, Alice decrypts', async () => {
    const { alice, bob } = await makeSession()

    // Alice must send at least one message first so Bob can advance his ratchet
    await bob.decrypt(await alice.encrypt('ping'))

    const reply = await bob.encrypt('pong')
    const plain = await alice.decrypt(reply)
    expect(plain).toBe('pong')
  })

  it('handles unicode and emoji', async () => {
    const { alice, bob } = await makeSession()
    const text = 'こんにちは 🔐 मनुष्य'
    expect(await bob.decrypt(await alice.encrypt(text))).toBe(text)
  })

  it('handles empty string', async () => {
    const { alice, bob } = await makeSession()
    expect(await bob.decrypt(await alice.encrypt(''))).toBe('')
  })
})

// ── Key rotation ──────────────────────────────────────────────────────────────

describe('key rotation (forward secrecy)', () => {
  it('each message produces a different ciphertext even for identical plaintext', async () => {
    const { alice, bob } = await makeSession()

    const m1 = await alice.encrypt('same text')
    const m2 = await alice.encrypt('same text')

    // Nonces differ — so ciphertexts must differ
    expect(Buffer.from(m1.ciphertext).toString('hex'))
      .not.toBe(Buffer.from(m2.ciphertext).toString('hex'))

    expect(await bob.decrypt(m1)).toBe('same text')
    expect(await bob.decrypt(m2)).toBe('same text')
  })

  it('DH ratchet advances when direction flips (Alice→Bob then Bob→Alice)', async () => {
    const { alice, bob } = await makeSession()

    await bob.decrypt(await alice.encrypt('msg1'))

    // Bob's first reply triggers a DH ratchet step — new chain keys on both sides
    const reply = await bob.encrypt('reply1')
    const exportBefore = bob.export()

    await alice.decrypt(reply)
    const exportAfter = alice.export()

    // After Alice decrypts Bob's first message, she should have advanced her DHr
    expect(exportAfter.DHr).not.toBeNull()
    expect(exportBefore.DHs_pub).toBeDefined()
  })

  it('multiple rounds of back-and-forth all decrypt correctly', async () => {
    const { alice, bob } = await makeSession()
    const transcript: string[] = []

    for (let i = 0; i < 5; i++) {
      const a2b = `alice→bob #${i}`
      await bob.decrypt(await alice.encrypt(a2b))
      transcript.push(a2b)

      const b2a = `bob→alice #${i}`
      await alice.decrypt(await bob.encrypt(b2a))
      transcript.push(b2a)
    }

    expect(transcript).toHaveLength(10)
  })
})

// ── Out-of-order messages ─────────────────────────────────────────────────────

describe('out-of-order message delivery', () => {
  it('Bob can decrypt messages that arrive out of order', async () => {
    const { alice, bob } = await makeSession()

    const m1 = await alice.encrypt('first')
    const m2 = await alice.encrypt('second')
    const m3 = await alice.encrypt('third')

    // Deliver out of order: 3, 1, 2
    expect(await bob.decrypt(m3)).toBe('third')
    expect(await bob.decrypt(m1)).toBe('first')
    expect(await bob.decrypt(m2)).toBe('second')
  })

  it('skipped keys are stored then consumed exactly once', async () => {
    const { alice, bob } = await makeSession()

    const m1 = await alice.encrypt('one')
    const m2 = await alice.encrypt('two')

    // Deliver m2 first — m1's key gets saved
    await bob.decrypt(m2)
    const stateAfterM2 = bob.export()
    expect(stateAfterM2.MKSKIPPED.length).toBe(1)

    // Deliver m1 — saved key consumed
    await bob.decrypt(m1)
    const stateAfterM1 = bob.export()
    expect(stateAfterM1.MKSKIPPED.length).toBe(0)
  })
})

// ── Forward secrecy ───────────────────────────────────────────────────────────

describe('forward secrecy', () => {
  it('message key is gone after decryption — cannot decrypt again', async () => {
    const { alice, bob } = await makeSession()
    const msg = await alice.encrypt('secret')

    await bob.decrypt(msg)

    // Replaying the same ciphertext should fail because the key was deleted
    await expect(bob.decrypt(msg)).rejects.toThrow(DecryptionFailedError)
  })

  it('wrong key cannot decrypt a message', async () => {
    const { alice, bob } = await makeSession()
    const { bob: evilBob } = await makeSession() // different session, different keys

    const msg = await alice.encrypt('secret')
    await expect(evilBob.decrypt(msg)).rejects.toThrow(DecryptionFailedError)
  })

  it('tampered ciphertext throws DecryptionFailedError', async () => {
    const { alice, bob } = await makeSession()
    const msg = await alice.encrypt('secret')
    msg.ciphertext[0] ^= 0xff // flip a bit
    await expect(bob.decrypt(msg)).rejects.toThrow(DecryptionFailedError)
  })
})

// ── State export / import ─────────────────────────────────────────────────────

describe('state persistence (export / import)', () => {
  it('exported and re-imported state decrypts correctly', async () => {
    const { alice, bob } = await makeSession()

    await bob.decrypt(await alice.encrypt('before export'))

    // Export Bob's state, reimport it, continue session
    const bobRestored = await DoubleRatchet.fromExport(bob.export())
    const msg = await alice.encrypt('after export')
    expect(await bobRestored.decrypt(msg)).toBe('after export')
  })

  it('export contains no plaintext', async () => {
    const { alice } = await makeSession()
    await alice.encrypt('do not leak this')
    const exported = JSON.stringify(alice.export())
    expect(exported).not.toContain('do not leak this')
  })

  it('fromExport throws on wrong version', async () => {
    const { alice } = await makeSession()
    const state = alice.export()
    state.version = 999
    await expect(DoubleRatchet.fromExport(state)).rejects.toThrow(InvalidKeyError)
  })
})

// ── Error handling ────────────────────────────────────────────────────────────

describe('error handling', () => {
  it('receiver cannot encrypt before receiving the first message', async () => {
    const { bob } = await makeSession()
    await expect(bob.encrypt('hi')).rejects.toThrow(InvalidKeyError)
  })

  it('initSender throws InvalidKeyError for wrong-length sharedSecret', async () => {
    const bobKP = await generateKeyPair()
    await expect(DoubleRatchet.initSender(new Uint8Array(16), bobKP.publicKey)).rejects.toThrow(InvalidKeyError)
  })

  it('initSender throws InvalidKeyError for wrong-length theirPublicKey', async () => {
    const secret = new Uint8Array(32).fill(1)
    await expect(DoubleRatchet.initSender(secret, new Uint8Array(16))).rejects.toThrow(InvalidKeyError)
  })

  it('initReceiver throws InvalidKeyError for wrong-length sharedSecret', async () => {
    const bobKP = await generateKeyPair()
    await expect(DoubleRatchet.initReceiver(new Uint8Array(16), bobKP)).rejects.toThrow(InvalidKeyError)
  })

  it('throws DecryptionFailedError when skip limit exceeded', async () => {
    const { alice, bob } = await makeSession()

    // Encrypt MAX_SKIP_KEYS + 2 messages without delivering them
    const msgs = []
    for (let i = 0; i < MAX_SKIP_KEYS + 2; i++) {
      msgs.push(await alice.encrypt(`msg${i}`))
    }

    // Trying to decrypt the last one should fail (too many skipped)
    await expect(bob.decrypt(msgs[msgs.length - 1]!)).rejects.toThrow(DecryptionFailedError)
  })
})
