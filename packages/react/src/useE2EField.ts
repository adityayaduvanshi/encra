import { useState, useEffect, useRef, useCallback } from 'react'
import { sodiumReady, generateFieldKey, encryptField, decryptField } from '@encra/core'
import type { EncryptedField } from '@encra/core'
import { loadFieldKey, saveFieldKey } from './ratchetStore.js'

export type { EncryptedField }

// ── Types ─────────────────────────────────────────────────────────────────────

export interface UseE2EFieldOptions {
  userId: string
  /** Optional: provide your own 32-byte key instead of auto-generating. */
  fieldKey?: Uint8Array
}

export interface UseE2EFieldResult {
  /** Encrypt a string value. Returns `{ ciphertext, nonce }` — store both in your DB. */
  encrypt:   (value: string) => Promise<EncryptedField>
  /** Decrypt a value produced by `encrypt`. */
  decrypt:   (encrypted: EncryptedField) => Promise<string>
  /** True once the key is initialised. Wait for this before calling encrypt/decrypt. */
  isReady:   boolean
  /** Fatal init error (e.g. libsodium failed to load). */
  error:     Error | null
  /** Export the symmetric key as base64url for backup or cross-device use. Returns null before ready. */
  exportKey: () => string | null
  /** Restore a key from a base64url backup. Saves to IndexedDB and updates the in-memory key. */
  setKey:    (b64: string) => Promise<void>
}

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * React hook for local symmetric field encryption.
 *
 * Encrypts individual string values (SSN, credit card, email) using
 * XSalsa20-Poly1305 with a 32-byte key auto-managed in IndexedDB.
 * No server, no recipient — only this device can encrypt/decrypt.
 *
 * Use `exportKey()` to back up the key and `setKey(b64)` to restore it
 * on another device or after clearing browser storage.
 *
 * @example
 * const { encrypt, decrypt, isReady, exportKey, setKey } = useE2EField({ userId })
 * const encrypted = await encrypt('123-45-6789')  // { ciphertext, nonce } → store in DB
 * const plain     = await decrypt(encrypted)       // '123-45-6789'
 * const key       = exportKey()                    // base64url — back this up
 * await setKey(key)                                // restore on new device
 */
export function useE2EField({ userId, fieldKey }: UseE2EFieldOptions): UseE2EFieldResult {
  const [isReady, setIsReady] = useState(false)
  const [error,   setError]   = useState<Error | null>(null)

  const keyRef    = useRef<Uint8Array | null>(null)
  const keyB64Ref = useRef<string | null>(null)

  // ── Init ────────────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false

    async function init() {
      try {
        const { default: sodium } = await import('libsodium-wrappers')
        await sodium.ready
        await sodiumReady()

        const B64 = sodium.base64_variants.URLSAFE_NO_PADDING

        if (fieldKey) {
          keyRef.current    = fieldKey
          keyB64Ref.current = sodium.to_base64(fieldKey, B64)
        } else {
          const stored = await loadFieldKey(userId)
          if (stored) {
            keyRef.current    = sodium.from_base64(stored, B64)
            keyB64Ref.current = stored
          } else {
            const key = await generateFieldKey()
            const b64 = sodium.to_base64(key, B64)
            keyRef.current    = key
            keyB64Ref.current = b64
            await saveFieldKey(userId, b64)
          }
        }

        if (!cancelled) setIsReady(true)
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)))
      }
    }

    void init()
    return () => { cancelled = true }
  }, [userId, fieldKey])

  // ── encrypt ──────────────────────────────────────────────────────────────────

  const encrypt = useCallback(async (value: string): Promise<EncryptedField> => {
    if (!keyRef.current) throw new Error('useE2EField is not ready. Wait for isReady.')
    return encryptField(value, keyRef.current)
  }, [])

  // ── decrypt ──────────────────────────────────────────────────────────────────

  const decrypt = useCallback(async (encrypted: EncryptedField): Promise<string> => {
    if (!keyRef.current) throw new Error('useE2EField is not ready. Wait for isReady.')
    return decryptField(encrypted, keyRef.current)
  }, [])

  // ── exportKey ─────────────────────────────────────────────────────────────────

  const exportKey = useCallback((): string | null => keyB64Ref.current, [])

  // ── setKey ────────────────────────────────────────────────────────────────────

  const setKey = useCallback(async (b64: string): Promise<void> => {
    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready
    const B64 = sodium.base64_variants.URLSAFE_NO_PADDING
    let bytes: Uint8Array
    try {
      bytes = sodium.from_base64(b64.trim(), B64)
    } catch {
      throw new Error('Invalid key format — paste the full base64url key.')
    }
    if (bytes.length !== sodium.crypto_secretbox_KEYBYTES) {
      throw new Error(`Invalid key: expected ${sodium.crypto_secretbox_KEYBYTES} bytes, got ${bytes.length}.`)
    }
    keyRef.current    = bytes
    keyB64Ref.current = b64.trim()
    await saveFieldKey(userId, b64.trim())
  }, [userId])

  return { encrypt, decrypt, isReady, error, exportKey, setKey }
}
