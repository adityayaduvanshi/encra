import _sodium from 'libsodium-wrappers'
import type { EncryptedField } from './field.js'
import { InvalidKeyError, DecryptionFailedError } from '../errors.js'

export type PresenceStatus = 'online' | 'offline' | 'away' | 'busy'

/**
 * Decrypted presence state broadcast over the relay.
 * All fields travel encrypted — the server never reads plaintext status,
 * last-seen times, or typing state.
 */
export interface PresencePayload {
  /** Current status of the user. */
  status: PresenceStatus
  /** Unix epoch ms — when this update was generated on the sender's device. */
  lastSeenAt: number
  /** True while the user is actively composing a message. */
  isTyping: boolean
}

/** Wire shape of an encrypted presence update — same structure as `EncryptedField`. */
export type EncryptedPresence = EncryptedField

/**
 * Derives a symmetric presence key from a 32-byte session secret.
 *
 * Uses keyed BLAKE2b-256 with domain separator `encra:presence:v1` so the key is
 * cryptographically isolated from message keys derived from the same secret.
 * Feed it the X3DH session root key: both parties compute the identical root key
 * during the handshake, so each side derives the same presence key with no extra
 * exchange. Because a fresh root key is produced every time a session is
 * (re-)established, the presence key rotates with the session — giving forward
 * secrecy at session granularity.
 *
 * @param sharedSecret - 32-byte secret (X3DH session root key, or an ECDH shared secret).
 * @returns 32-byte symmetric presence key.
 * @throws {InvalidKeyError} If sharedSecret is not 32 bytes.
 * @example
 * const { sessionKeys } = await x3dhInitiate(myIdentity, theirBundle)
 * const presenceKey = await derivePresenceKey(sessionKeys.rootKey)
 */
export async function derivePresenceKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  if (sharedSecret.length !== 32) {
    throw new InvalidKeyError(`sharedSecret must be 32 bytes, got ${sharedSecret.length}.`)
  }
  // UTF-8 bytes of 'encra:presence:v1' as a literal Uint8Array (message).
  // sharedSecret is the keyed-BLAKE2b key; this mirrors the prf(key, data) pattern
  // in ratchet.ts and avoids from_string/TextEncoder jsdom type mismatches.
  const domain = new Uint8Array([101, 110, 99, 114, 97, 58, 112, 114, 101, 115, 101, 110, 99, 101, 58, 118, 49])
  return new Uint8Array(_sodium.crypto_generichash(32, domain, sharedSecret))
}

const B64 = () => _sodium.base64_variants.URLSAFE_NO_PADDING

/**
 * Encrypts a presence payload with a symmetric presence key.
 * Uses XSalsa20-Poly1305 with a fresh random nonce per call.
 *
 * Passes the JSON string directly to `crypto_secretbox_easy` (sodium accepts strings
 * as message input) to avoid cross-environment Uint8Array constructor mismatches.
 *
 * @param payload     - Presence data (status, lastSeenAt, isTyping).
 * @param presenceKey - 32-byte key from `derivePresenceKey`.
 * @returns `EncryptedPresence` with URL-safe base64 ciphertext and nonce.
 * @throws {InvalidKeyError} If the key is the wrong size.
 * @example
 * const enc = await encryptPresence({ status: 'online', lastSeenAt: Date.now(), isTyping: false }, key)
 */
export async function encryptPresence(
  payload: PresencePayload,
  presenceKey: Uint8Array,
): Promise<EncryptedPresence> {
  await _sodium.ready
  if (presenceKey.length !== _sodium.crypto_secretbox_KEYBYTES) {
    throw new InvalidKeyError(
      `presenceKey must be ${_sodium.crypto_secretbox_KEYBYTES} bytes, got ${presenceKey.length}.`,
    )
  }
  const json       = JSON.stringify(payload)
  const nonce      = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES)
  const ciphertext = _sodium.crypto_secretbox_easy(json, nonce, presenceKey)
  return {
    ciphertext: _sodium.to_base64(new Uint8Array(ciphertext), B64()),
    nonce:      _sodium.to_base64(new Uint8Array(nonce),      B64()),
  }
}

/**
 * Decrypts an encrypted presence payload.
 *
 * @param encrypted   - Object produced by `encryptPresence`.
 * @param presenceKey - 32-byte key from `derivePresenceKey`.
 * @returns Decrypted `PresencePayload`.
 * @throws {DecryptionFailedError} If MAC fails or the JSON payload is malformed.
 * @example
 * const payload = await decryptPresence(enc, key)
 * console.log(payload.status) // 'online'
 */
export async function decryptPresence(
  encrypted: EncryptedPresence,
  presenceKey: Uint8Array,
): Promise<PresencePayload> {
  await _sodium.ready
  let ctBytes: Uint8Array
  let nonceBytes: Uint8Array
  try {
    ctBytes    = _sodium.from_base64(encrypted.ciphertext, B64())
    nonceBytes = _sodium.from_base64(encrypted.nonce,      B64())
  } catch {
    throw new DecryptionFailedError('decryptPresence: invalid base64 in encrypted presence.')
  }
  let plain: Uint8Array | null
  try {
    plain = _sodium.crypto_secretbox_open_easy(ctBytes, nonceBytes, presenceKey)
  } catch {
    throw new DecryptionFailedError()
  }
  if (!plain) throw new DecryptionFailedError()
  try {
    return JSON.parse(_sodium.to_string(plain)) as PresencePayload
  } catch {
    throw new DecryptionFailedError('Failed to parse decrypted presence payload.')
  }
}
