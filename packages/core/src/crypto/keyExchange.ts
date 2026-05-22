import _sodium from 'libsodium-wrappers'
import { InvalidKeyError } from '../errors.js'

/**
 * Derives a shared secret from one party's private key and the other's public key.
 * Both parties will derive the same secret: deriveSharedSecret(alicePriv, bobPub) ===
 * deriveSharedSecret(bobPriv, alicePub).
 *
 * Uses X25519 (crypto_scalarmult) as exposed by libsodium.
 *
 * @param myPrivateKey  - Caller's X25519 private key (32 bytes).
 * @param theirPublicKey - Counterpart's X25519 public key (32 bytes).
 * @returns 32-byte shared secret. Never send this over the network.
 * @throws {InvalidKeyError} If either key is the wrong length.
 * @example
 * const secret = deriveSharedSecret(alice.privateKey, bob.publicKey)
 */
export async function deriveSharedSecret(
  myPrivateKey: Uint8Array,
  theirPublicKey: Uint8Array
): Promise<Uint8Array> {
  await _sodium.ready
  const na = _sodium

  if (myPrivateKey.length !== na.crypto_box_SECRETKEYBYTES) {
    throw new InvalidKeyError(
      `Private key must be ${na.crypto_box_SECRETKEYBYTES} bytes, got ${myPrivateKey.length}.`
    )
  }
  if (theirPublicKey.length !== na.crypto_box_PUBLICKEYBYTES) {
    throw new InvalidKeyError(
      `Public key must be ${na.crypto_box_PUBLICKEYBYTES} bytes, got ${theirPublicKey.length}.`
    )
  }

  return na.crypto_scalarmult(myPrivateKey, theirPublicKey)
}
