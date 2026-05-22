/**
 * Alice→Bob integration test.
 *
 * Full encrypt/decrypt flow using the real crypto layer (no mocks) and an
 * in-process Express server backed by an in-memory key store.  No database
 * or Redis infrastructure required.
 */
import { describe, it, expect, beforeAll } from 'vitest'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import { createApp } from '../src/app.js'
import { setPool } from '../src/db/pool.js'
import type { Pool, QueryResult } from 'pg'
import { vi } from 'vitest'

// ── In-memory pool ────────────────────────────────────────────────────────────

function makeInMemoryPool(): Pool {
  const keys = new Map<string, string>()
  return {
    query: vi.fn(async (sql: string, params: unknown[]) => {
      const s = sql.trim().toUpperCase()
      if (s.startsWith('INSERT INTO PUBLIC_KEYS')) {
        keys.set(params[0] as string, params[1] as string)
        return { rows: [], rowCount: 1 } as unknown as QueryResult
      }
      if (s.startsWith('SELECT USER_ID, PUBLIC_KEY FROM PUBLIC_KEYS')) {
        const key = keys.get(params[0] as string)
        return key
          ? { rows: [{ user_id: params[0], public_key: key }], rowCount: 1 } as unknown as QueryResult
          : { rows: [], rowCount: 0 } as unknown as QueryResult
      }
      return { rows: [], rowCount: 0 } as unknown as QueryResult
    }),
  } as unknown as Pool
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const JWT_SECRET = 'test-secret-do-not-use-in-production'
const TOKEN = jwt.sign({ developerId: 'test-dev' }, JWT_SECRET, { expiresIn: '1h' })

async function registerKey(app: ReturnType<typeof createApp>, userId: string, publicKey: string) {
  const res = await request(app)
    .post('/v1/keys')
    .set('Authorization', `Bearer ${TOKEN}`)
    .send({ userId, publicKey })
  expect(res.status).toBe(201)
}

async function fetchPublicKey(app: ReturnType<typeof createApp>, userId: string): Promise<string> {
  const res = await request(app)
    .get(`/v1/keys/${userId}`)
    .set('Authorization', `Bearer ${TOKEN}`)
  expect(res.status).toBe(200)
  return (res.body as { publicKey: string }).publicKey
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Alice → Bob end-to-end flow', () => {
  // Lazy-import core to avoid libsodium ESM issue (same alias workaround not needed
  // here — we rely on the CJS path via require resolution in Node's module loader)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let core: any

  beforeAll(async () => {
    // Import after sodium is ready; the dynamic import ensures libsodium initialises
    core = await import('@encra/core')
    await core.sodiumReady()
    setPool(makeInMemoryPool())
  })

  it('Alice registers her public key and it is retrievable', async () => {
    const app = createApp()
    const alice = await core.generateKeyPair()
    const alicePubB64 = core.exportKey(alice.publicKey)

    await registerKey(app, 'alice', alicePubB64)
    const fetched = await fetchPublicKey(app, 'alice')
    expect(fetched).toBe(alicePubB64)
  })

  it('Alice encrypts a message that Bob can decrypt', async () => {
    const app = createApp()

    // 1. Both generate key pairs
    const alice = await core.generateKeyPair()
    const bob = await core.generateKeyPair()

    // 2. Register public keys
    await registerKey(app, 'alice-e2e', core.exportKey(alice.publicKey))
    await registerKey(app, 'bob-e2e', core.exportKey(bob.publicKey))

    // 3. Alice fetches Bob's public key and derives shared secret
    const bobPubB64 = await fetchPublicKey(app, 'bob-e2e')
    const bobPub = core.importKey(bobPubB64)
    const aliceShared = await core.deriveSharedSecret(alice.privateKey, bobPub)

    // 4. Alice encrypts her message
    const plaintext = 'Hello Bob! This message is end-to-end encrypted.'
    const { ciphertext, nonce } = await core.encrypt(plaintext, aliceShared)

    // 5. Security check — ciphertext must not equal plaintext bytes
    const encoder = new TextEncoder()
    expect(ciphertext).not.toEqual(encoder.encode(plaintext))

    // 6. Bob derives shared secret from his side
    const alicePubB64 = await fetchPublicKey(app, 'alice-e2e')
    const alicePub = core.importKey(alicePubB64)
    const bobShared = await core.deriveSharedSecret(bob.privateKey, alicePub)

    // 7. Both shared secrets are identical (ECDH symmetry)
    expect(aliceShared).toEqual(bobShared)

    // 8. Bob decrypts — gets back the original plaintext
    const decrypted = await core.decrypt(ciphertext, nonce, bobShared)
    expect(decrypted).toBe(plaintext)
  })

  it('ciphertext cannot be decrypted with the wrong key', async () => {
    const app = createApp()

    const alice = await core.generateKeyPair()
    const bob   = await core.generateKeyPair()
    const carol = await core.generateKeyPair()

    await registerKey(app, 'alice-sec', core.exportKey(alice.publicKey))
    await registerKey(app, 'bob-sec',   core.exportKey(bob.publicKey))

    const bobPub = core.importKey(await fetchPublicKey(app, 'bob-sec'))
    const aliceShared = await core.deriveSharedSecret(alice.privateKey, bobPub)

    const { ciphertext, nonce } = await core.encrypt('Top secret', aliceShared)

    // Carol has no relation to this conversation — her key cannot decrypt it
    const carolShared = await core.deriveSharedSecret(carol.privateKey, alice.publicKey)

    await expect(core.decrypt(ciphertext, nonce, carolShared)).rejects.toThrow(core.DecryptionFailedError)
  })

  it('fingerprints are deterministic per key pair', async () => {
    const alice = await core.generateKeyPair()
    const fp1 = await core.generateFingerprint(alice.publicKey)
    const fp2 = await core.generateFingerprint(alice.publicKey)
    expect(fp1).toBe(fp2)
    expect(fp1).toMatch(/^(\d{5} ){11}\d{5}$/)
  })
})
