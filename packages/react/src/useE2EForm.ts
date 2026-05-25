import { useState, useEffect, useRef, useCallback } from 'react'
import {
  generateKeyPair,
  exportKey,
  importKey,
  sodiumReady,
  DecryptionFailedError,
} from '@encra/core'
import type { KeyPair } from '@encra/core'
import {
  loadKeyPair, saveKeyPair,
  getOrCreateDeviceId,
} from './ratchetStore.js'
import type { DeviceKey } from './useE2EChat.js'

// ── Public types ──────────────────────────────────────────────────────────────

/**
 * Encrypted form fields produced by `encryptFields`.
 *
 * Each device of the recipient gets a separate set of encrypted field values
 * so they can independently decrypt the form on any of their devices. Store
 * or transmit the entire object together with the plaintext field names.
 */
export interface EncryptedFields {
  /**
   * One envelope per recipient device.
   * Each device's fields are encrypted with the shared secret derived from
   * the sender's key and that device's public key.
   */
  devices: Array<{
    /** The recipient's device UUID. */
    deviceId: string
    /** Field name → `{ ciphertext, nonce }` (base64url, no padding). */
    fields: Record<string, { ciphertext: string; nonce: string }>
  }>
}

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
   * Encrypts once per registered device of the recipient so the form is
   * accessible on all their devices.
   *
   * @param fields - Plain object of `{ fieldName: plaintext }`.
   * @param to     - The recipient's `userId`. They must have registered a public key.
   * @returns `EncryptedFields` — one device envelope per registered device.
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
   * Finds the envelope for the current device, then tries each of the sender's
   * device keys until decryption succeeds.
   *
   * @param encrypted - The object returned by `encryptFields`.
   * @param from      - The sender's `userId`.
   * @returns The original `{ fieldName: plaintext }` object.
   * @throws {DecryptionFailedError} If no matching key is found or any field fails to decrypt.
   */
  decryptFields: (encrypted: EncryptedFields, from: string) => Promise<Record<string, string>>

  /** True once the key pair is initialised and registered with the server. */
  isReady: boolean

  /** Fatal initialisation error (e.g. server unreachable, key registration failed). */
  error: Error | null
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ENCRA_SERVER_URL = 'https://api.encra.dev'
/** Re-fetch peer device list after this many ms — ensures new devices are seen. */
const PEER_KEY_TTL_MS  = 5 * 60 * 1_000

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * React hook for encrypting and decrypting form field values end-to-end.
 *
 * Each field is encrypted independently with XSalsa20-Poly1305 and a fresh random
 * nonce, using an X25519 shared secret derived from the sender and recipient's key
 * pairs. Field names are sent in plaintext; only the values are encrypted.
 *
 * Multi-device: if the recipient has multiple registered devices, the fields are
 * encrypted once per device so every device can decrypt them independently.
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

  const keyPairRef          = useRef<KeyPair | null>(null)
  const deviceIdRef         = useRef<string>('')
  const peerKeyCacheRef     = useRef<Map<string, DeviceKey[]>>(new Map())
  const peerKeyCacheTimeRef = useRef<Map<string, number>>(new Map())
  const httpBase            = serverUrl.replace(/\/$/, '')

  // ── Init ────────────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false

    async function init() {
      try {
        await sodiumReady()

        // Get or create a stable device ID for this browser/device
        const deviceId = await getOrCreateDeviceId(userId)
        deviceIdRef.current = deviceId

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

        // Register public key + deviceId (idempotent upsert)
        const res = await fetch(`${httpBase}/v1/keys`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
          body:    JSON.stringify({
            userId,
            publicKey: exportKey(keyPairRef.current.publicKey),
            deviceId,
          }),
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

  /**
   * Fetches all registered device keys for `peerId` and caches them in memory.
   *
   * @param peerId - The target user's identifier.
   * @returns Array of DeviceKey (one per registered device).
   * @throws {Error} If the server request fails.
   */
  const fetchPeerDeviceKeys = useCallback(async (peerId: string): Promise<DeviceKey[]> => {
    const cached   = peerKeyCacheRef.current.get(peerId)
    const cachedAt = peerKeyCacheTimeRef.current.get(peerId) ?? 0
    if (cached && Date.now() - cachedAt < PEER_KEY_TTL_MS) return cached

    const res = await fetch(`${httpBase}/v1/keys/${peerId}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
    if (!res.ok) {
      throw new Error(
        `Could not fetch public keys for '${peerId}': ${res.status}. ` +
        `Make sure ${peerId} has registered.`
      )
    }
    const { devices } = (await res.json()) as {
      userId:  string
      devices: Array<{ deviceId: string; publicKey: string }>
    }
    const deviceKeys: DeviceKey[] = devices.map((d) => ({
      deviceId:  d.deviceId,
      publicKey: importKey(d.publicKey),
    }))
    peerKeyCacheRef.current.set(peerId, deviceKeys)
    peerKeyCacheTimeRef.current.set(peerId, Date.now())
    return deviceKeys
  }, [httpBase, apiKey])

  // ── encryptFields ────────────────────────────────────────────────────────────

  /**
   * Encrypts each field value for every registered device of `to`.
   *
   * Uses `crypto_box_beforenm` (X25519 + HSalsa20) to derive a per-device
   * symmetric key. Each field gets a unique random nonce. The result contains
   * one complete set of encrypted fields per recipient device.
   *
   * @param fields - Plain object of string field values.
   * @param to     - The recipient's `userId`.
   * @returns `EncryptedFields` with one `devices` entry per registered device.
   */
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

    const peerDevices = await fetchPeerDeviceKeys(to)
    if (peerDevices.length === 0) {
      throw new Error(`No devices found for '${to}'. Make sure they have registered.`)
    }

    // Single dynamic import so ECDH and secretbox run in the same libsodium
    // instance — avoids Uint8Array cross-realm rejection when modules are
    // inlined separately (e.g. jsdom/Vitest environment with server.deps.inline).
    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready
    const B64       = sodium.base64_variants.URLSAFE_NO_PADDING
    const myPrivKey = keyPairRef.current.privateKey.slice()

    const deviceEnvelopes: EncryptedFields['devices'] = []

    for (const device of peerDevices) {
      // crypto_box_beforenm = crypto_scalarmult + HSalsa20 key derivation.
      // Produces a key suitable for crypto_secretbox (unlike raw scalarmult output).
      // .slice() copies WASM-heap bytes into plain ArrayBuffers so this sodium
      // instance accepts key material originating from @encra/core's instance.
      const shared = sodium.crypto_box_beforenm(device.publicKey.slice(), myPrivKey)

      const encryptedFields: Record<string, { ciphertext: string; nonce: string }> = {}

      for (const [key, value] of Object.entries(fields)) {
        if (typeof value !== 'string') {
          throw new TypeError(`encryptFields: field "${key}" must be a string, got ${typeof value}.`)
        }
        const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        // Pass the value as a string — libsodium converts it internally with its
        // own from_string(), avoiding jsdom's TextEncoder cross-realm Uint8Array issue.
        const ciphertext = sodium.crypto_secretbox_easy(value, nonce, shared)
        encryptedFields[key] = {
          ciphertext: sodium.to_base64(ciphertext, B64),
          nonce:      sodium.to_base64(nonce, B64),
        }
      }

      deviceEnvelopes.push({ deviceId: device.deviceId, fields: encryptedFields })
    }

    return { devices: deviceEnvelopes }
  }, [isReady, fetchPeerDeviceKeys])

  // ── decryptFields ────────────────────────────────────────────────────────────

  /**
   * Decrypts `encrypted` using the current device's field envelope.
   *
   * Finds the `devices` entry matching this device's ID, then tries each of
   * the sender's registered public keys until one successfully decrypts all fields.
   *
   * @param encrypted - The `EncryptedFields` produced by `encryptFields`.
   * @param from      - The sender's `userId`.
   * @returns The original `{ fieldName: plaintext }` object.
   * @throws {DecryptionFailedError} If no matching key is found or any field fails.
   */
  const decryptFields = useCallback(async (
    encrypted: EncryptedFields,
    from: string,
  ): Promise<Record<string, string>> => {
    if (!keyPairRef.current) {
      throw new Error('useE2EForm is not ready yet. Wait for isReady before calling decryptFields.')
    }

    // Find the envelope addressed to this device
    const myDeviceId = deviceIdRef.current
    const myEnvelope = encrypted.devices.find((d) => d.deviceId === myDeviceId)
    if (!myEnvelope) {
      throw new DecryptionFailedError(
        `No envelope found for device '${myDeviceId}'. ` +
        `These fields were not encrypted for this device.`
      )
    }

    // Fetch all of the sender's device keys and try each one
    const senderDevices = await fetchPeerDeviceKeys(from)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready
    const B64       = sodium.base64_variants.URLSAFE_NO_PADDING
    const myPrivKey = keyPairRef.current.privateKey.slice()

    for (const senderDevice of senderDevices) {
      try {
        const shared  = sodium.crypto_box_beforenm(senderDevice.publicKey.slice(), myPrivKey)
        const result: Record<string, string> = {}

        for (const [key, { ciphertext, nonce }] of Object.entries(myEnvelope.fields)) {
          const ctBytes    = sodium.from_base64(ciphertext, B64)
          const nonceBytes = sodium.from_base64(nonce, B64)
          const plainBytes = sodium.crypto_secretbox_open_easy(ctBytes, nonceBytes, shared)
          result[key] = sodium.to_string(plainBytes)
        }

        return result
      } catch {
        // Wrong sender device key or corrupted data — try the next one
      }
    }

    throw new DecryptionFailedError(
      `Field decryption failed — no matching key found for sender '${from}'.`
    )
  }, [fetchPeerDeviceKeys])

  return { encryptFields, decryptFields, isReady, error }
}
