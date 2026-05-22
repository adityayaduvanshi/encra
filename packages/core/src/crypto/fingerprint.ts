import _sodium from 'libsodium-wrappers'
import { InvalidKeyError } from '../errors.js'

/**
 * Generates a human-readable safety number (fingerprint) for a public key.
 * Users can compare these out-of-band to verify they are talking to the right person.
 *
 * Produces a 60-character decimal string split into 12 groups of 5 digits, matching
 * the Signal safety number format for familiarity.
 *
 * @param publicKey - X25519 public key (32 bytes).
 * @returns Formatted fingerprint string, e.g. "12345 67890 11234 ...".
 * @throws {InvalidKeyError} If `publicKey` is not 32 bytes.
 * @example
 * const fp = generateFingerprint(alice.publicKey)
 * // "05371 28491 ..."
 */
export async function generateFingerprint(publicKey: Uint8Array): Promise<string> {
  await _sodium.ready
  const na = _sodium

  if (publicKey.length !== na.crypto_box_PUBLICKEYBYTES) {
    throw new InvalidKeyError(
      `Public key must be ${na.crypto_box_PUBLICKEYBYTES} bytes, got ${publicKey.length}.`
    )
  }

  const hash = na.crypto_generichash(32, publicKey)

  const digits = Array.from(hash)
    .map((b) => b.toString().padStart(3, '0'))
    .join('')
    .slice(0, 60)

  return digits.match(/.{5}/g)!.join(' ')
}
