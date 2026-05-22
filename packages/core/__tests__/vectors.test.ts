/**
 * Test vectors — hardcoded inputs/outputs to catch regressions in the crypto layer.
 * These were generated once from known-good runs and must never change without a
 * deliberate algorithm version bump.
 */
import { describe, it, expect } from 'vitest'
import { importKey, exportKey, sodiumReady } from '../src/crypto/keyPair.js'
import { deriveSharedSecret } from '../src/crypto/keyExchange.js'
import { decrypt } from '../src/crypto/encrypt.js'
import { generateFingerprint } from '../src/crypto/fingerprint.js'

// Fixed key pairs derived from deterministic seeds (0xaa×32 for Alice, 0xbb×32 for Bob)
// Generated via crypto_box_seed_keypair — see scripts/gen-vectors.cjs
const ALICE_PRIVATE_B64 = 'Bd-N2enqx2ChtowVZTiLHpMEmxVbqogIz0tJhfhmW6g'
const ALICE_PUBLIC_B64  = 'VSKR8CyTF1GWMwITAtD3ujmxzzIxDiPueqakMSrkoCc'
const BOB_PRIVATE_B64   = 'eMPkaRs5-FrHvi50JRSrHyzoljLhAhxVXh1njfSa9Iw'
const BOB_PUBLIC_B64    = 'iLfQ_rHb3Jze-iqBRQPuK75UaOF6PQBo5Pgjvy-U0UI'

// Ciphertext produced by crypto_secretbox_easy('Hello, World!', nonce=0x42×24, sharedSecret)
const VECTOR_NONCE_B64      = 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC'
const VECTOR_CIPHERTEXT_B64 = 'O5Y-ZPARrs3X-reQW6EtFqaFnxyZTi8LHizZiQY'
const VECTOR_PLAINTEXT      = 'Hello, World!'

describe('crypto test vectors', () => {
  it('importKey / exportKey are stable', async () => {
    await sodiumReady()
    const key = importKey(ALICE_PUBLIC_B64)
    expect(exportKey(key)).toBe(ALICE_PUBLIC_B64)
  })

  it('shared secret derivation is stable (Alice ↔ Bob)', async () => {
    const alicePriv = importKey(ALICE_PRIVATE_B64)
    const bobPub    = importKey(BOB_PUBLIC_B64)
    const bobPriv   = importKey(BOB_PRIVATE_B64)
    const alicePub  = importKey(ALICE_PUBLIC_B64)

    const secretAB = await deriveSharedSecret(alicePriv, bobPub)
    const secretBA = await deriveSharedSecret(bobPriv, alicePub)

    expect(secretAB).toEqual(secretBA)
    // Ensure the secret is stable across runs (deterministic per key pair)
    const secretAB2 = await deriveSharedSecret(alicePriv, bobPub)
    expect(secretAB).toEqual(secretAB2)
  })

  it('decrypts known ciphertext vector to expected plaintext', async () => {
    const alicePriv = importKey(ALICE_PRIVATE_B64)
    const bobPub    = importKey(BOB_PUBLIC_B64)
    const secret    = await deriveSharedSecret(alicePriv, bobPub)

    const ciphertext = importKey(VECTOR_CIPHERTEXT_B64)
    const nonce      = importKey(VECTOR_NONCE_B64)

    const plaintext = await decrypt(ciphertext, nonce, secret)
    expect(plaintext).toBe(VECTOR_PLAINTEXT)
  })

  it('generateFingerprint is stable for a known public key', async () => {
    const pub = importKey(ALICE_PUBLIC_B64)
    const fp1 = await generateFingerprint(pub)
    const fp2 = await generateFingerprint(pub)
    expect(fp1).toBe(fp2)
    // Fingerprint format: 12 groups of 5 digits separated by spaces
    expect(fp1).toMatch(/^(\d{5} ){11}\d{5}$/)
  })
})
