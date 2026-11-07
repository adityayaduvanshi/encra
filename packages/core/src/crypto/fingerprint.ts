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
  return formatFingerprint(hash)
}

/**
 * Generates a symmetric safety number for a conversation between two parties.
 *
 * Unlike {@link generateFingerprint} (which fingerprints a single key), this
 * combines *both* parties' public keys so the two sides independently compute
 * the **same** 60-digit code. Users compare it out-of-band (read it aloud, scan
 * a QR, etc.) to detect a man-in-the-middle: if a malicious key server
 * substituted either identity key, the two safety numbers will differ.
 *
 * The inputs are sorted before hashing, so `generateSafetyNumber(a, b)` and
 * `generateSafetyNumber(b, a)` produce identical output.
 *
 * @param keyA - One party's public key (32 bytes). Typically an identity key.
 * @param keyB - The other party's public key (32 bytes).
 * @returns Formatted 60-digit safety number, e.g. `"12345 67890 ..."`.
 * @throws {InvalidKeyError} If either key is not 32 bytes.
 * @example
 * const sn = await generateSafetyNumber(myIdentityKey, theirIdentityKey)
 * // Show `sn` in both clients; users confirm they match.
 */
export async function generateSafetyNumber(keyA: Uint8Array, keyB: Uint8Array): Promise<string> {
  await _sodium.ready
  const na = _sodium

  for (const [name, key] of [['keyA', keyA], ['keyB', keyB]] as const) {
    if (key.length !== na.crypto_box_PUBLICKEYBYTES) {
      throw new InvalidKeyError(
        `${name} must be ${na.crypto_box_PUBLICKEYBYTES} bytes, got ${key.length}.`
      )
    }
  }

  // Sort the two keys so both participants hash the same byte sequence.
  const [first, second] = compareBytes(keyA, keyB) <= 0 ? [keyA, keyB] : [keyB, keyA]
  const combined = new Uint8Array(first.length + second.length)
  combined.set(first, 0)
  combined.set(second, first.length)

  return formatFingerprint(na.crypto_generichash(32, combined))
}

/** Lexicographic comparison of two equal-length byte arrays. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length && i < b.length; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!
  }
  return a.length - b.length
}

/** Render a hash as a 60-digit code split into 12 groups of 5 (Signal format). */
function formatFingerprint(hash: Uint8Array): string {
  const digits = Array.from(hash)
    .map((b) => b.toString().padStart(3, '0'))
    .join('')
    .slice(0, 60)

  return digits.match(/.{5}/g)!.join(' ')
}
