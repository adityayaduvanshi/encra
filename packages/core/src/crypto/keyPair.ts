import _sodium from 'libsodium-wrappers'
import { InvalidKeyError } from '../errors.js'

export interface KeyPair {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

/**
 * Initialises libsodium (idempotent — safe to call multiple times).
 * Must be awaited before any other crypto function.
 */
export async function sodiumReady(): Promise<void> {
  await _sodium.ready
}

function sodium() {
  return _sodium
}

/**
 * Generates an X25519 key pair for ECDH key exchange.
 *
 * @returns A fresh `{ publicKey, privateKey }` pair as raw Uint8Arrays.
 * @example
 * await sodiumReady()
 * const alice = await generateKeyPair()
 */
export async function generateKeyPair(): Promise<KeyPair> {
  await _sodium.ready
  const na = sodium()
  const pair = na.crypto_box_keypair()
  return { publicKey: pair.publicKey, privateKey: pair.privateKey }
}

/**
 * Encodes a raw key to a URL-safe base64 string for transport.
 *
 * @param key - Raw key bytes.
 * @returns Base64-encoded string.
 * @throws {InvalidKeyError} If `key` is empty.
 * @example
 * const b64 = exportKey(alice.publicKey)
 */
export function exportKey(key: Uint8Array): string {
  if (key.length === 0) throw new InvalidKeyError('Cannot export an empty key.')
  return _sodium.to_base64(key, _sodium.base64_variants.URLSAFE_NO_PADDING)
}

/**
 * Decodes a base64 string back to raw key bytes.
 *
 * @param b64 - URL-safe base64 string produced by `exportKey`.
 * @returns Raw key bytes.
 * @throws {InvalidKeyError} If the string is not valid base64.
 * @example
 * const key = importKey(b64String)
 */
export function importKey(b64: string): Uint8Array {
  if (!b64 || b64.trim().length === 0) throw new InvalidKeyError('Cannot import an empty key string.')
  try {
    return _sodium.from_base64(b64, _sodium.base64_variants.URLSAFE_NO_PADDING)
  } catch {
    throw new InvalidKeyError(`Invalid base64 key string: "${b64.slice(0, 20)}..."`)
  }
}
