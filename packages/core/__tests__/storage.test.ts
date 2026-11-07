import { describe, it, expect, beforeAll } from 'vitest'
import {
  sodiumReady,
  generateStorageRootKey,
  deriveConversationKey,
  encryptForStorage,
  decryptFromStorage,
  type ChatMessage,
} from '../src/index.js'
import { DecryptionFailedError, InvalidKeyError } from '../src/errors.js'

const msg = (over: Partial<ChatMessage> = {}): ChatMessage => ({
  id:             'm1',
  conversationId: 'bob',
  from:           'alice',
  to:             'bob',
  text:           'secret 🔐',
  timestamp:      1700000000000,
  ...over,
})

describe('at-rest message storage', () => {
  beforeAll(async () => { await sodiumReady() })

  it('round-trips a message through encrypt/decrypt for storage', async () => {
    const root = await generateStorageRootKey()
    const rec  = await encryptForStorage(msg(), root)
    const out  = await decryptFromStorage(rec, root)
    expect(out).toEqual(msg())
  })

  it('keeps id, conversationId, and timestamp as queryable plaintext; hides the rest', async () => {
    const root = await generateStorageRootKey()
    const rec  = await encryptForStorage(msg(), root)
    expect(rec.id).toBe('m1')
    expect(rec.conversationId).toBe('bob')
    expect(rec.timestamp).toBe(1700000000000)
    // Sensitive content must not appear in the record.
    const blob = JSON.stringify(rec)
    expect(blob).not.toContain('secret')
    expect(blob).not.toContain('alice')
  })

  it('uses a fresh nonce each call (ciphertext differs for identical input)', async () => {
    const root = await generateStorageRootKey()
    const a = await encryptForStorage(msg(), root)
    const b = await encryptForStorage(msg(), root)
    expect(a.ciphertext).not.toBe(b.ciphertext)
    expect(a.nonce).not.toBe(b.nonce)
  })

  it('derives independent keys per conversation', async () => {
    const root = await generateStorageRootKey()
    const k1 = await deriveConversationKey(root, 'bob')
    const k2 = await deriveConversationKey(root, 'carol')
    const k1again = await deriveConversationKey(root, 'bob')
    expect(Buffer.from(k1).equals(Buffer.from(k1again))).toBe(true)
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false)
  })

  it('fails to decrypt a record from the wrong conversation key', async () => {
    const root = await generateStorageRootKey()
    const rec  = await encryptForStorage(msg({ conversationId: 'bob' }), root)
    // Tamper the conversationId so a different key is derived on decrypt.
    const forged = { ...rec, conversationId: 'carol' }
    await expect(decryptFromStorage(forged, root)).rejects.toThrow(DecryptionFailedError)
  })

  it('rejects a non-32-byte root key', async () => {
    await expect(deriveConversationKey(new Uint8Array(16), 'bob')).rejects.toThrow(InvalidKeyError)
  })
})
