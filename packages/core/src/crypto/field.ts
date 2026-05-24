import _sodium from 'libsodium-wrappers'
import { InvalidKeyError, DecryptionFailedError } from '../errors.js'

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * The result of `encryptField` — a pair of URL-safe base64 strings
 * ready to store in a database column.
 */
export interface EncryptedField {
  /** XSalsa20-Poly1305 ciphertext, URL-safe base64 encoded. */
  ciphertext: string
  /** Random 24-byte nonce, URL-safe base64 encoded. Must be stored alongside the ciphertext. */
  nonce: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const B64 = () => _sodium.base64_variants.URLSAFE_NO_PADDING

function toB64(bytes: Uint8Array): string {
  return _sodium.to_base64(bytes, B64())
}

function fromB64(b64: string, label: string): Uint8Array {
  try {
    return _sodium.from_base64(b64, B64())
  } catch {
    throw new InvalidKeyError(`Invalid base64 for ${label}.`)
  }
}

// ── encryptField ──────────────────────────────────────────────────────────────

/**
 * Encrypts a single string value with a 32-byte symmetric key.
 *
 * Uses XSalsa20-Poly1305 (authenticated encryption) with a fresh random nonce
 * per call — the same key can be reused safely across many fields. Designed for
 * database field encryption: both outputs are URL-safe base64 strings that fit
 * in a single `TEXT` column or a small JSON blob.
 *
 * This is a standalone utility — no server, no key exchange, no React required.
 * Pair it with `generateFieldKey()` to create a key, or derive one from an
 * existing shared secret via `deriveSharedSecret`.
 *
 * @param value - UTF-8 plaintext value to encrypt (e.g. an SSN, email, or note).
 * @param key   - 32-byte symmetric key (`Uint8Array`). Generate with `generateFieldKey()`.
 * @returns `{ ciphertext, nonce }` — both as URL-safe base64. Store both together.
 * @throws {InvalidKeyError} If `key` is not exactly 32 bytes, or `value` is not a string.
 *
 * @example
 * const key = await generateFieldKey()
 * const { ciphertext, nonce } = await encryptField('123-45-6789', key)
 * // store ciphertext + nonce in your DB
 */
export async function encryptField(value: string, key: Uint8Array): Promise<EncryptedField> {
  await _sodium.ready
  const na = _sodium

  if (typeof value !== 'string') {
    throw new InvalidKeyError('encryptField: value must be a string.')
  }
  if (!(key instanceof Uint8Array) || key.length !== na.crypto_secretbox_KEYBYTES) {
    throw new InvalidKeyError(
      `encryptField: key must be a ${na.crypto_secretbox_KEYBYTES}-byte Uint8Array, ` +
      `got ${key instanceof Uint8Array ? key.length : typeof key} bytes.`
    )
  }

  const nonce      = na.randombytes_buf(na.crypto_secretbox_NONCEBYTES)
  const message    = na.from_string(value)
  const ciphertext = na.crypto_secretbox_easy(message, nonce, key)

  return { ciphertext: toB64(ciphertext), nonce: toB64(nonce) }
}

// ── decryptField ──────────────────────────────────────────────────────────────

/**
 * Decrypts a value produced by `encryptField`.
 *
 * @param encrypted - The `{ ciphertext, nonce }` object returned by `encryptField`.
 * @param key       - The same 32-byte key used to encrypt.
 * @returns Decrypted UTF-8 plaintext.
 * @throws {DecryptionFailedError} If authentication fails (wrong key, tampered data, bad base64).
 * @throws {InvalidKeyError} If `key` is not exactly 32 bytes.
 *
 * @example
 * const ssn = await decryptField({ ciphertext, nonce }, key)
 */
export async function decryptField(encrypted: EncryptedField, key: Uint8Array): Promise<string> {
  await _sodium.ready
  const na = _sodium

  if (!(key instanceof Uint8Array) || key.length !== na.crypto_secretbox_KEYBYTES) {
    throw new InvalidKeyError(
      `decryptField: key must be a ${na.crypto_secretbox_KEYBYTES}-byte Uint8Array.`
    )
  }

  let ctBytes: Uint8Array
  let nonceBytes: Uint8Array
  try {
    ctBytes    = fromB64(encrypted.ciphertext, 'ciphertext')
    nonceBytes = fromB64(encrypted.nonce, 'nonce')
  } catch {
    throw new DecryptionFailedError('decryptField: invalid base64 in encrypted field.')
  }

  let plaintext: Uint8Array | null
  try {
    plaintext = na.crypto_secretbox_open_easy(ctBytes, nonceBytes, key)
  } catch {
    throw new DecryptionFailedError()
  }

  if (!plaintext) throw new DecryptionFailedError()

  return na.to_string(plaintext)
}

// ── generateFieldKey ──────────────────────────────────────────────────────────

/**
 * Generates a fresh 32-byte symmetric key for use with `encryptField`.
 *
 * Uses libsodium's CSPRNG (`randombytes_buf`). Store the result securely —
 * in an environment variable, a secrets manager, or encrypted at rest.
 * Never commit it to source control.
 *
 * @returns A 32-byte `Uint8Array` suitable for `encryptField` / `decryptField`.
 *
 * @example
 * const key = await generateFieldKey()
 * // Export to base64 for storage:
 * const b64Key = exportKey(key)
 * // Restore from base64:
 * const key = importKey(b64Key)
 */
export async function generateFieldKey(): Promise<Uint8Array> {
  await _sodium.ready
  return _sodium.randombytes_buf(_sodium.crypto_secretbox_KEYBYTES)
}
