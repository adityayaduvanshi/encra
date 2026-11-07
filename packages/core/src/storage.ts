import _sodium from 'libsodium-wrappers'
import { encryptField, decryptField, generateFieldKey } from './crypto/field.js'
import { InvalidKeyError, DecryptionFailedError } from './errors.js'

/**
 * At-rest chat message storage.
 *
 * The Double Ratchet that moves messages over the wire is forward-secret: a
 * message key is deleted the instant the message is decrypted, so ratchet
 * ciphertext can be decrypted exactly once. It is transport encryption, NOT
 * storage — you cannot keep it in a database and re-decrypt it later.
 *
 * To persist history, re-encrypt each message at rest under a long-lived,
 * per-conversation storage key that never leaves the client. `encryptForStorage`
 * produces a record whose sensitive content is ciphertext but whose `id`,
 * `conversationId`, and `timestamp` stay in the clear so your database can index,
 * filter, and paginate on them. On load you fetch a page of records and call
 * `decryptFromStorage` on each. Because each record is independently encrypted
 * (its own nonce), decryption is random-access — you only decrypt the page you
 * show, never the whole history.
 */

/** A decrypted chat message (structurally compatible with the SDK `Message`). */
export interface ChatMessage {
  id:             string
  conversationId: string
  from:           string
  to:             string
  text:           string
  timestamp:      number
}

/**
 * A message encrypted for at-rest storage in your database.
 *
 * `id`, `conversationId`, and `timestamp` are plaintext so you can index and
 * paginate (`WHERE conversation_id = $1 ORDER BY timestamp DESC LIMIT $2`). The
 * sender, recipient, and text live inside `ciphertext` — your database (and the
 * Encra server) only ever hold ciphertext.
 */
export interface StoredMessageRecord {
  id:             string
  conversationId: string
  timestamp:      number
  /** XSalsa20-Poly1305 ciphertext of `{ from, to, text }`, URL-safe base64. */
  ciphertext:     string
  /** Random nonce, URL-safe base64. */
  nonce:          string
}

/**
 * Generate a fresh 32-byte storage root key. Hold ONE of these per user,
 * client-side (e.g. in IndexedDB); derive a per-conversation key from it with
 * {@link deriveConversationKey}. Back it up (e.g. passphrase-wrapped) to restore
 * history on a new device — it is never sent to any server.
 */
export async function generateStorageRootKey(): Promise<Uint8Array> {
  return generateFieldKey()
}

/**
 * Derive a per-conversation storage key from the storage root key via keyed
 * BLAKE2b-256 with the domain separator `encra:storage:v1:<conversationId>`.
 * Each conversation gets an independent key, so compromising one doesn't expose
 * the others.
 *
 * @throws {InvalidKeyError} If `rootKey` is not 32 bytes.
 */
export async function deriveConversationKey(rootKey: Uint8Array, conversationId: string): Promise<Uint8Array> {
  await _sodium.ready
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== 32) {
    throw new InvalidKeyError(`storage root key must be a 32-byte Uint8Array, got ${rootKey instanceof Uint8Array ? rootKey.length : typeof rootKey}.`)
  }
  // Pass the domain as a string (libsodium UTF-8 encodes it internally). Avoids
  // `from_string`, which returns a cross-realm Uint8Array that crypto_generichash
  // rejects under jsdom.
  return new Uint8Array(_sodium.crypto_generichash(32, `encra:storage:v1:${conversationId}`, rootKey))
}

/**
 * Encrypt a message for at-rest storage. Derives the conversation key from
 * `rootKey` + `message.conversationId`, then encrypts `{ from, to, text }`.
 *
 * @example
 * const record = await encryptForStorage(message, rootKey)
 * await db.insert('messages', record)   // only ciphertext + queryable metadata
 */
export async function encryptForStorage(message: ChatMessage, rootKey: Uint8Array): Promise<StoredMessageRecord> {
  const key = await deriveConversationKey(rootKey, message.conversationId)
  const enc = await encryptField(JSON.stringify({ from: message.from, to: message.to, text: message.text }), key)
  return {
    id:             message.id,
    conversationId: message.conversationId,
    timestamp:      message.timestamp,
    ciphertext:     enc.ciphertext,
    nonce:          enc.nonce,
  }
}

/**
 * Decrypt a record produced by {@link encryptForStorage} back into a message.
 *
 * @throws {DecryptionFailedError} If the key is wrong, the record was tampered
 *   with, or the payload is malformed.
 *
 * @example
 * const page = await db.query('… ORDER BY timestamp DESC LIMIT 50')
 * const messages = await Promise.all(page.map((r) => decryptFromStorage(r, rootKey)))
 */
export async function decryptFromStorage(record: StoredMessageRecord, rootKey: Uint8Array): Promise<ChatMessage> {
  const key = await deriveConversationKey(rootKey, record.conversationId)
  const raw = await decryptField({ ciphertext: record.ciphertext, nonce: record.nonce }, key)
  let parsed: { from: string; to: string; text: string }
  try {
    parsed = JSON.parse(raw) as { from: string; to: string; text: string }
  } catch {
    throw new DecryptionFailedError('decryptFromStorage: malformed record payload.')
  }
  return {
    id:             record.id,
    conversationId: record.conversationId,
    from:           parsed.from,
    to:             parsed.to,
    text:           parsed.text,
    timestamp:      record.timestamp,
  }
}
