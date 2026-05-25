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
 * An encrypted file produced by `encryptFile`.
 *
 * The file bytes are encrypted once per recipient device so that every device
 * can independently decrypt the file with its own key. Store or transmit the
 * entire object — all fields are required to decrypt.
 */
export interface EncryptedFile {
  /** Original filename (e.g. `"photo.jpg"`). Stored as plaintext metadata. */
  name: string
  /** MIME type (e.g. `"image/jpeg"`). Stored as plaintext metadata. */
  mimeType: string
  /** Original file size in bytes (pre-encryption). */
  size: number
  /**
   * One encryption envelope per recipient device.
   * Each entry is independently encrypted with the shared secret derived from
   * the sender's key and that specific device's public key.
   */
  devices: Array<{
    /** The recipient's device UUID (matches `deviceId` in their key registration). */
    deviceId:   string
    /** XSalsa20-Poly1305 ciphertext of the raw file bytes. */
    ciphertext: Uint8Array
    /** Random 24-byte nonce. Must be stored alongside `ciphertext`. */
    nonce:      Uint8Array
  }>
}

export interface UseE2EFileOptions {
  apiKey: string
  userId: string
  /** Defaults to the Encra managed server. */
  serverUrl?: string
  /** Called on any error (key fetch failure, decrypt failure, etc.). */
  onError?: (err: Error) => void
}

export interface UseE2EFileResult {
  /**
   * Encrypt a `File` or `Blob` for a recipient.
   *
   * Encrypts the file once per registered device of the recipient so that the
   * file is accessible on all their devices simultaneously.
   *
   * @param file - The file or blob to encrypt.
   * @param to   - The recipient's `userId`. They must have registered a public key.
   * @returns An `EncryptedFile` object. Send or store it however you like.
   * @throws {Error} If the hook is not yet ready or the recipient's key cannot be fetched.
   * @throws {RangeError} If `file.size` exceeds `MAX_FILE_BYTES` (50 MB).
   */
  encryptFile: (file: File | Blob, to: string) => Promise<EncryptedFile>

  /**
   * Decrypt an `EncryptedFile` from a sender.
   *
   * Finds the envelope for the current device, then tries each of the sender's
   * device keys until decryption succeeds.
   *
   * @param encrypted - The object returned by `encryptFile`.
   * @param from      - The sender's `userId`.
   * @returns A `File` with the original filename and MIME type restored.
   * @throws {DecryptionFailedError} If no matching key is found or data is tampered.
   */
  decryptFile: (encrypted: EncryptedFile, from: string) => Promise<File>

  /** True once the key pair is initialised and registered with the server. */
  isReady: boolean

  /** Fatal initialisation error (e.g. server unreachable, key registration failed). */
  error: Error | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Read a File or Blob into a Uint8Array.
 * Uses `.arrayBuffer()` if available (modern browsers), otherwise falls back to FileReader.
 */
function readFileBytes(file: File | Blob): Promise<Uint8Array> {
  if (typeof file.arrayBuffer === 'function') {
    return file.arrayBuffer().then((buf) => new Uint8Array(buf))
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload  = () => resolve(new Uint8Array(reader.result as ArrayBuffer))
    reader.onerror = () => reject(reader.error ?? new Error('FileReader error'))
    reader.readAsArrayBuffer(file)
  })
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ENCRA_SERVER_URL = 'https://api.encra.dev'
/** Re-fetch peer device list after this many ms — ensures new devices are seen. */
const PEER_KEY_TTL_MS  = 5 * 60 * 1_000

/** Maximum file size supported in a single encrypt call (50 MB). */
export const MAX_FILE_BYTES = 50 * 1024 * 1024

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * React hook for encrypting and decrypting files end-to-end.
 *
 * Uses the same X25519 key pair as `useE2EChat` — users share one identity
 * across Encra hooks. Encryption uses XSalsa20-Poly1305 authenticated encryption
 * with a per-file, per-device derived key.
 *
 * Multi-device: if the recipient has multiple registered devices, the file is
 * encrypted once per device so every device can decrypt it independently.
 *
 * Files up to 50 MB are supported. The encrypted bytes live in memory as
 * `Uint8Array` — you decide how to store or transmit them (S3, IPFS, your DB, etc.).
 * The server never sees the plaintext.
 *
 * @example
 * const { encryptFile, decryptFile, isReady } = useE2EFile({
 *   apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
 *   userId: currentUser,
 * })
 *
 * // Encrypt a file for Bob (all of Bob's devices get an envelope)
 * const encrypted = await encryptFile(file, 'bob')
 *
 * // Decrypt a file from Alice (finds the envelope for this device automatically)
 * const decrypted = await decryptFile(encryptedFromAlice, 'alice')
 * const url = URL.createObjectURL(decrypted)
 */
export function useE2EFile({
  apiKey,
  userId,
  serverUrl = ENCRA_SERVER_URL,
  onError,
}: UseE2EFileOptions): UseE2EFileResult {
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

        // Restore or generate stable key pair (shared with useE2EChat, useE2EForm)
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

  // ── encryptFile ──────────────────────────────────────────────────────────────

  /**
   * Encrypts `file` for every registered device of `to`.
   *
   * Uses `crypto_box_beforenm` (X25519 + HSalsa20) to derive a per-device
   * symmetric key, then encrypts the raw file bytes with XSalsa20-Poly1305.
   * Each device gets its own `{ ciphertext, nonce }` envelope.
   *
   * @param file - The file or blob to encrypt.
   * @param to   - The recipient's `userId`.
   * @returns `EncryptedFile` with one `devices` entry per registered device.
   */
  const encryptFile = useCallback(async (file: File | Blob, to: string): Promise<EncryptedFile> => {
    if (!isReady || !keyPairRef.current) {
      throw new Error('useE2EFile is not ready yet. Wait for isReady before calling encryptFile.')
    }

    const name     = file instanceof File ? file.name : 'file'
    const mimeType = file.type || 'application/octet-stream'
    const size     = file.size

    if (size > MAX_FILE_BYTES) {
      throw new RangeError(
        `File too large: ${size} bytes. Maximum supported size is ${MAX_FILE_BYTES} bytes (50 MB).`
      )
    }

    const peerDevices = await fetchPeerDeviceKeys(to)
    if (peerDevices.length === 0) {
      throw new Error(`No devices found for '${to}'. Make sure they have registered.`)
    }

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready

    const fileBytes = await readFileBytes(file)
    const myPrivKey = keyPairRef.current.privateKey.slice()

    const deviceEnvelopes: EncryptedFile['devices'] = []

    for (const device of peerDevices) {
      // crypto_box_beforenm = crypto_scalarmult + HSalsa20 key derivation.
      // Produces a key suitable for crypto_secretbox (unlike raw scalarmult output).
      const shared      = sodium.crypto_box_beforenm(device.publicKey.slice(), myPrivKey)
      const nonce       = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
      const ciphertext  = sodium.crypto_secretbox_easy(fileBytes, nonce, shared)
      deviceEnvelopes.push({ deviceId: device.deviceId, ciphertext, nonce })
    }

    return { name, mimeType, size, devices: deviceEnvelopes }
  }, [isReady, fetchPeerDeviceKeys])

  // ── decryptFile ──────────────────────────────────────────────────────────────

  /**
   * Decrypts `encrypted` using the current device's envelope.
   *
   * Finds the `devices` entry matching this device's ID, then tries each of
   * the sender's registered public keys until one successfully decrypts the
   * ciphertext.
   *
   * @param encrypted - The `EncryptedFile` produced by `encryptFile`.
   * @param from      - The sender's `userId`.
   * @returns The original `File` with name and MIME type restored.
   * @throws {DecryptionFailedError} If no key produces a valid decryption.
   */
  const decryptFile = useCallback(async (encrypted: EncryptedFile, from: string): Promise<File> => {
    if (!keyPairRef.current) {
      throw new Error('useE2EFile is not ready yet. Wait for isReady before calling decryptFile.')
    }

    // Find the envelope addressed to this device
    const myDeviceId = deviceIdRef.current
    const myEnvelope = encrypted.devices.find((d) => d.deviceId === myDeviceId)
    if (!myEnvelope) {
      throw new DecryptionFailedError(
        `No envelope found for device '${myDeviceId}'. ` +
        `This file was not encrypted for this device.`
      )
    }

    // Fetch all of the sender's device keys and try each one
    const senderDevices = await fetchPeerDeviceKeys(from)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready

    const myPrivKey = keyPairRef.current.privateKey.slice()

    for (const senderDevice of senderDevices) {
      try {
        const shared     = sodium.crypto_box_beforenm(senderDevice.publicKey.slice(), myPrivKey)
        const plainBytes = sodium.crypto_secretbox_open_easy(
          myEnvelope.ciphertext,
          myEnvelope.nonce,
          shared,
        )
        // Slice to a plain ArrayBuffer so TypeScript's BlobPart type is satisfied
        const buf = plainBytes.buffer.slice(
          plainBytes.byteOffset,
          plainBytes.byteOffset + plainBytes.byteLength,
        ) as ArrayBuffer
        return new File([buf], encrypted.name, { type: encrypted.mimeType })
      } catch {
        // Wrong sender device key — try the next one
      }
    }

    throw new DecryptionFailedError(
      `File decryption failed — no matching key found for sender '${from}'.`
    )
  }, [fetchPeerDeviceKeys])

  return { encryptFile, decryptFile, isReady, error }
}
