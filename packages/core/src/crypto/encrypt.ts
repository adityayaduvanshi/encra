import _sodium from 'libsodium-wrappers'
import { DecryptionFailedError, InvalidKeyError } from '../errors.js'

export interface EncryptedMessage {
  ciphertext: Uint8Array
  nonce: Uint8Array
}

/**
 * Encrypts a UTF-8 plaintext string using XSalsa20-Poly1305 with a random nonce.
 * The nonce is generated fresh for every call — never reused.
 *
 * @param plaintext    - UTF-8 message to encrypt.
 * @param sharedSecret - 32-byte shared secret from `deriveSharedSecret`.
 * @returns `{ ciphertext, nonce }` — both must be stored/transmitted together.
 * @throws {InvalidKeyError} If `sharedSecret` is not 32 bytes.
 * @example
 * const { ciphertext, nonce } = encrypt('Hello Bob', sharedSecret)
 */
export async function encrypt(plaintext: string, sharedSecret: Uint8Array): Promise<EncryptedMessage> {
  await _sodium.ready
  const na = _sodium

  if (sharedSecret.length !== na.crypto_secretbox_KEYBYTES) {
    throw new InvalidKeyError(
      `Shared secret must be ${na.crypto_secretbox_KEYBYTES} bytes, got ${sharedSecret.length}.`
    )
  }
  if (typeof plaintext !== 'string') {
    throw new InvalidKeyError('plaintext must be a string.')
  }

  const nonce = na.randombytes_buf(na.crypto_secretbox_NONCEBYTES)
  const message = na.from_string(plaintext)
  const ciphertext = na.crypto_secretbox_easy(message, nonce, sharedSecret)

  return { ciphertext, nonce }
}

/**
 * Decrypts a ciphertext produced by `encrypt`.
 *
 * @param ciphertext   - Encrypted bytes from `encrypt`.
 * @param nonce        - Nonce from `encrypt` (must match the one used to encrypt).
 * @param sharedSecret - 32-byte shared secret from `deriveSharedSecret`.
 * @returns Decrypted UTF-8 plaintext.
 * @throws {DecryptionFailedError} If authentication fails (wrong key, tampered data).
 * @throws {InvalidKeyError} If `sharedSecret` is not 32 bytes.
 * @example
 * const text = decrypt(ciphertext, nonce, sharedSecret)
 */
export async function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  sharedSecret: Uint8Array
): Promise<string> {
  await _sodium.ready
  const na = _sodium

  if (sharedSecret.length !== na.crypto_secretbox_KEYBYTES) {
    throw new InvalidKeyError(
      `Shared secret must be ${na.crypto_secretbox_KEYBYTES} bytes, got ${sharedSecret.length}.`
    )
  }

  let plaintext: Uint8Array | null
  try {
    plaintext = na.crypto_secretbox_open_easy(ciphertext, nonce, sharedSecret)
  } catch {
    throw new DecryptionFailedError()
  }

  if (!plaintext) throw new DecryptionFailedError()

  return na.to_string(plaintext)
}
