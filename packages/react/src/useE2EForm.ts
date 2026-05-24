import { useState, useEffect, useRef, useCallback } from 'react'
import {
  generateKeyPair,
  exportKey,
  importKey,
  sodiumReady,
  DecryptionFailedError,
} from '@encra/core'
import type { KeyPair } from '@encra/core'
import { loadKeyPair, saveKeyPair } from './ratchetStore.js'

// ── Public types ──────────────────────────────────────────────────────────────

/**
 * A map of field names to their encrypted values, ready to submit or store.
 * Each field is independently encrypted with the same derived shared secret
 * and a unique random nonce — compromising one field's nonce doesn't affect others.
 */
export type EncryptedFields = Record<string, { ciphertext: string; nonce: string }>

export interface UseE2EFormOptions {
  apiKey: string
  userId: string
  /** Defaults to the Encra managed server. */
  serverUrl?: string
  /** Called on any error (key fetch failure, decrypt failure, etc.). */
  onError?: (err: Error) => void
}

export interface UseE2EFormResult {
  /**
   * Encrypt a flat object of string field values for a recipient.
   *
   * Every field is encrypted independently with a unique nonce. Field names
   * (keys) are **not** encrypted — only the values are. If you need key
   * privacy, hash the field names before passing them in.
   *
   * @param fields - Plain object of `{ fieldName: plaintext }`.
   * @param to     - The recipient's `userId`. They must have registered a public key.
   * @returns `EncryptedFields` — an object with the same keys, values replaced by `{ ciphertext, nonce }`.
   * @throws {Error} If the hook is not yet ready or the recipient's key cannot be fetched.
   *
   * @example
   * const payload = await encryptFields({ email: 'alice@example.com', ssn: '123-45-6789' }, 'doctor')
   * await fetch('/api/submit', { method: 'POST', body: JSON.stringify(payload) })
   */
  encryptFields: (fields: Record<string, string>, to: string) => Promise<EncryptedFields>

  /**
   * Decrypt an `EncryptedFields` object — the inverse of `encryptFields`.
   *
   * @param encrypted - The object returned by `encryptFields`.
   * @param from      - The sender's `userId`.
   * @returns The original `{ fieldName: plaintext }` object.
   * @throws {DecryptionFailedError} If any field fails to decrypt.
   */
  decryptFields: (encrypted: EncryptedFields, from: string) => Promise<Record<string, string>>

  /** True once the key pair is initialised and registered with the server. */
  isReady: boolean

  /** Fatal initialisation error (e.g. server unreachable, key registration failed). */
  error: Error | null
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ENCRA_SERVER_URL = 'https://api.encra.dev'

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * React hook for encrypting and decrypting form field values end-to-end.
 *
 * Each field is encrypted independently with XSalsa20-Poly1305 and a fresh random
 * nonce, using an X25519 shared secret derived from the sender and recipient's key
 * pairs. Field names are sent in plaintext; only the values are encrypted.
 *
 * Ideal for HIPAA forms, private surveys, secure feedback, or any scenario where
 * your server must store data but must not be able to read it.
 *
 * The hook shares the same IndexedDB key pair as `useE2EChat` and `useE2EFile` —
 * a user has one cryptographic identity across all Encra hooks.
 *
 * @example
 * const { encryptFields, decryptFields, isReady } = useE2EForm({
 *   apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
 *   userId: currentUser,
 * })
 *
 * // Encrypt a form before submitting
 * const payload = await encryptFields(
 *   { name: 'Alice', ssn: '123-45-6789', notes: 'Private notes...' },
 *   'doctor-userId',
 * )
 * await fetch('/api/submit', { method: 'POST', body: JSON.stringify(payload) })
 *
 * // Decrypt on the recipient's side
 * const fields = await decryptFields(payload, 'patient-userId')
 * console.log(fields.ssn) // '123-45-6789'
 */
export function useE2EForm({
  apiKey,
  userId,
  serverUrl = ENCRA_SERVER_URL,
  onError,
}: UseE2EFormOptions): UseE2EFormResult {
  const [isReady, setIsReady] = useState(false)
  const [error,   setError]   = useState<Error | null>(null)

  const keyPairRef   = useRef<KeyPair | null>(null)
  const peerKeyCache = useRef<Map<string, Uint8Array>>(new Map())
  const httpBase     = serverUrl.replace(/\/$/, '')

  // ── Init ────────────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false

    async function init() {
      try {
        await sodiumReady()

        // Restore or generate stable key pair (shared with useE2EChat, useE2EFile)
        const stored = await loadKeyPair(userId)
        if (stored) {
          keyPairRef.current = {
            publicKey:  importKey(stored.pub),
            privateKey: importKey(stored.priv),
          }
        } else {
          const kp = await generateKeyPair()
          keyPairRef.current = kp
          await saveKeyPair(userId, {
            pub:  exportKey(kp.publicKey),
            priv: exportKey(kp.privateKey),
          })
        }

        // Register public key (idempotent upsert)
        const res = await fetch(`${httpBase}/v1/keys`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
          body:    JSON.stringify({ userId, publicKey: exportKey(keyPairRef.current.publicKey) }),
        })
        if (!res.ok) throw new Error(`Key registration failed: ${res.status}`)

        if (!cancelled) setIsReady(true)
      } catch (err) {
        if (!cancelled) {
          const e = err instanceof Error ? err : new Error(String(err))
          setError(e)
          onError?.(e)
        }
      }
    }

    void init()
    return () => { cancelled = true }
  }, [userId, apiKey, httpBase]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Peer key helper ──────────────────────────────────────────────────────────

  const fetchPeerKey = useCallback(async (peerId: string): Promise<Uint8Array> => {
    const cached = peerKeyCache.current.get(peerId)
    if (cached) return cached

    const res = await fetch(`${httpBase}/v1/keys/${peerId}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (!res.ok) {
      throw new Error(
        `Could not fetch public key for '${peerId}': ${res.status}. ` +
        `Make sure ${peerId} has registered.`
      )
    }
    const { publicKey: b64 } = (await res.json()) as { publicKey: string }
    const key = importKey(b64)
    peerKeyCache.current.set(peerId, key)
    return key
  }, [httpBase, apiKey])

  // ── encryptFields ────────────────────────────────────────────────────────────

  const encryptFields = useCallback(async (
    fields: Record<string, string>,
    to: string,
  ): Promise<EncryptedFields> => {
    if (!isReady || !keyPairRef.current) {
      throw new Error('useE2EForm is not ready yet. Wait for isReady before calling encryptFields.')
    }
    if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) {
      throw new TypeError('encryptFields: fields must be a plain object of string values.')
    }

    const peerPub = await fetchPeerKey(to)

    // Single dynamic import so ECDH and secretbox run in the same libsodium
    // instance — avoids Uint8Array cross-realm rejection when modules are
    // inlined separately (e.g. jsdom/Vitest environment with server.deps.inline).
    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready
    const B64 = sodium.base64_variants.URLSAFE_NO_PADDING

    // .slice() copies WASM-heap bytes to a plain ArrayBuffer so this sodium
    // instance can accept the key material generated by @encra/core's instance.
    const shared = sodium.crypto_scalarmult(
      keyPairRef.current.privateKey.slice(),
      peerPub.slice(),
    )

    const result: EncryptedFields = {}

    for (const [key, value] of Object.entries(fields)) {
      if (typeof value !== 'string') {
        throw new TypeError(`encryptFields: field "${key}" must be a string, got ${typeof value}.`)
      }
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
      // Pass the value as a string — libsodium converts it internally with its
      // own from_string(), avoiding jsdom's TextEncoder cross-realm Uint8Array issue.
      const ciphertext = sodium.crypto_secretbox_easy(value, nonce, shared)
      result[key] = {
        ciphertext: sodium.to_base64(ciphertext, B64),
        nonce:      sodium.to_base64(nonce, B64),
      }
    }

    return result
  }, [isReady, fetchPeerKey])

  // ── decryptFields ────────────────────────────────────────────────────────────

  const decryptFields = useCallback(async (
    encrypted: EncryptedFields,
    from: string,
  ): Promise<Record<string, string>> => {
    if (!keyPairRef.current) {
      throw new Error('useE2EForm is not ready yet. Wait for isReady before calling decryptFields.')
    }

    const peerPub = await fetchPeerKey(from)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready
    const B64 = sodium.base64_variants.URLSAFE_NO_PADDING

    const shared = sodium.crypto_scalarmult(
      keyPairRef.current.privateKey.slice(),
      peerPub.slice(),
    )

    const result: Record<string, string> = {}

    for (const [key, { ciphertext, nonce }] of Object.entries(encrypted)) {
      let ctBytes: Uint8Array
      let nonceBytes: Uint8Array
      try {
        ctBytes    = sodium.from_base64(ciphertext, B64)
        nonceBytes = sodium.from_base64(nonce, B64)
      } catch {
        throw new DecryptionFailedError(`decryptFields: invalid base64 for field "${key}".`)
      }

      let plainBytes: Uint8Array | null
      try {
        plainBytes = sodium.crypto_secretbox_open_easy(ctBytes, nonceBytes, shared)
      } catch {
        throw new DecryptionFailedError(`decryptFields: decryption failed for field "${key}".`)
      }

      if (!plainBytes) {
        throw new DecryptionFailedError(`decryptFields: authentication failed for field "${key}".`)
      }

      result[key] = sodium.to_string(plainBytes)
    }

    return result
  }, [fetchPeerKey])

  return { encryptFields, decryptFields, isReady, error }
}
