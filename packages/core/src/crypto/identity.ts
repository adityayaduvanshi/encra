import _sodium from 'libsodium-wrappers'
import { InvalidKeyError } from '../errors.js'

/**
 * A long-term identity key pair (Ed25519).
 *
 * The identity key is the cryptographic root of a user's identity. It is used
 * to sign prekeys (so peers can verify the server didn't substitute them) and,
 * after conversion to X25519, as a Diffie-Hellman input in the X3DH handshake.
 *
 * Unlike the per-session ratchet keys, the identity key is long-lived: it is
 * generated once per device and never rotated under normal operation. Its
 * public half is what safety-number fingerprints are computed over.
 */
export interface IdentityKeyPair {
  /** Ed25519 public key (32 bytes). */
  publicKey: Uint8Array
  /** Ed25519 secret key (64 bytes — includes the seed and public key). */
  privateKey: Uint8Array
}

/**
 * Generates a long-term Ed25519 identity key pair.
 *
 * @returns A fresh `{ publicKey, privateKey }` pair as raw Uint8Arrays.
 * @example
 * await sodiumReady()
 * const identity = await generateIdentityKeyPair()
 */
export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  await _sodium.ready
  const pair = _sodium.crypto_sign_keypair()
  return { publicKey: pair.publicKey, privateKey: pair.privateKey }
}

/**
 * Produces a detached Ed25519 signature over `message`.
 *
 * @param privateKey - Ed25519 secret key (64 bytes).
 * @param message    - Bytes to sign.
 * @returns 64-byte detached signature.
 * @throws {InvalidKeyError} If the secret key is the wrong length.
 * @example
 * const sig = await sign(identity.privateKey, signedPreKey.publicKey)
 */
export async function sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  if (privateKey.length !== _sodium.crypto_sign_SECRETKEYBYTES) {
    throw new InvalidKeyError(
      `Identity secret key must be ${_sodium.crypto_sign_SECRETKEYBYTES} bytes, got ${privateKey.length}.`
    )
  }
  return new Uint8Array(_sodium.crypto_sign_detached(message, privateKey))
}

/**
 * Verifies a detached Ed25519 signature.
 *
 * @param publicKey - Ed25519 public key (32 bytes) of the alleged signer.
 * @param message   - The bytes that were supposedly signed.
 * @param signature - 64-byte detached signature.
 * @returns `true` if the signature is valid, `false` otherwise. Never throws on
 *   a bad signature — only on a malformed public key.
 * @throws {InvalidKeyError} If the public key is the wrong length.
 * @example
 * const ok = await verify(theirIdentityPub, signedPreKeyPub, signature)
 * if (!ok) throw new Error('Prekey signature invalid — possible MITM.')
 */
export async function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  await _sodium.ready
  if (publicKey.length !== _sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new InvalidKeyError(
      `Identity public key must be ${_sodium.crypto_sign_PUBLICKEYBYTES} bytes, got ${publicKey.length}.`
    )
  }
  if (signature.length !== _sodium.crypto_sign_BYTES) return false
  try {
    return _sodium.crypto_sign_verify_detached(signature, message, publicKey)
  } catch {
    return false
  }
}

/**
 * Converts an Ed25519 *public* key to its X25519 (Montgomery) equivalent so the
 * identity key can be used as a Diffie-Hellman input in X3DH.
 *
 * @param edPublicKey - Ed25519 public key (32 bytes).
 * @returns X25519 public key (32 bytes).
 * @throws {InvalidKeyError} If the input is the wrong length.
 */
export function identityPublicToX25519(edPublicKey: Uint8Array): Uint8Array {
  if (edPublicKey.length !== _sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new InvalidKeyError(
      `Ed25519 public key must be ${_sodium.crypto_sign_PUBLICKEYBYTES} bytes, got ${edPublicKey.length}.`
    )
  }
  return new Uint8Array(_sodium.crypto_sign_ed25519_pk_to_curve25519(edPublicKey))
}

/**
 * Converts an Ed25519 *secret* key to its X25519 (Montgomery) equivalent so the
 * identity key can be used as a Diffie-Hellman input in X3DH.
 *
 * @param edPrivateKey - Ed25519 secret key (64 bytes).
 * @returns X25519 secret key (32 bytes).
 * @throws {InvalidKeyError} If the input is the wrong length.
 */
export function identityPrivateToX25519(edPrivateKey: Uint8Array): Uint8Array {
  if (edPrivateKey.length !== _sodium.crypto_sign_SECRETKEYBYTES) {
    throw new InvalidKeyError(
      `Ed25519 secret key must be ${_sodium.crypto_sign_SECRETKEYBYTES} bytes, got ${edPrivateKey.length}.`
    )
  }
  return new Uint8Array(_sodium.crypto_sign_ed25519_sk_to_curve25519(edPrivateKey))
}
