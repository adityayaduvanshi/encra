import { useState, useEffect, useRef, useCallback } from 'react'
import {
  generateKeyPair,
  deriveSharedSecret,
  exportKey,
  importKey,
  sodiumReady,
  InvalidKeyError,
  DecryptionFailedError,
} from '@encra/core'
import type { KeyPair } from '@encra/core'
import { loadKeyPair, saveKeyPair } from './ratchetStore.js'

// ── Public types ──────────────────────────────────────────────────────────────

/**
 * An encrypted file produced by `encryptFile`.
 * All fields are required to decrypt — store or transmit them together.
 */
export interface EncryptedFile {
  /** XSalsa20-Poly1305 ciphertext of the raw file bytes. */
  ciphertext: Uint8Array
  /** Random 24-byte nonce. Must be stored alongside `ciphertext`. */
  nonce: Uint8Array
  /** Original filename (e.g. `"photo.jpg"`). Stored as plaintext metadata. */
  name: string
  /** MIME type (e.g. `"image/jpeg"`). Stored as plaintext metadata. */
  mimeType: string
  /** Original file size in bytes (pre-encryption). */
  size: number
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
   * @param file - The file or blob to encrypt.
   * @param to   - The recipient's `userId`. They must have registered a public key.
   * @returns An `EncryptedFile` object. Send or store it however you like.
   * @throws {Error} If the hook is not yet ready or the recipient's key cannot be fetched.
   */
  encryptFile: (file: File | Blob, to: string) => Promise<EncryptedFile>

  /**
   * Decrypt an `EncryptedFile` from a sender.
   *
   * @param encrypted - The object returned by `encryptFile`.
   * @param from      - The sender's `userId`.
   * @returns A `File` with the original filename and MIME type restored.
   * @throws {DecryptionFailedError} If the key is wrong or the data is tampered.
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

/** Maximum file size supported in a single encrypt call (50 MB). */
export const MAX_FILE_BYTES = 50 * 1024 * 1024

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * React hook for encrypting and decrypting files end-to-end.
 *
 * Uses the same X25519 key pair as `useE2EChat` — users share one identity
 * across Encra hooks. Encryption uses XSalsa20-Poly1305 authenticated encryption
 * with a per-file derived key.
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
 * // Encrypt a file for Bob
 * const encrypted = await encryptFile(file, 'bob')
 *
 * // Decrypt a file from Alice
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

  const keyPairRef    = useRef<KeyPair | null>(null)
  const peerKeyCache  = useRef<Map<string, Uint8Array>>(new Map())
  const httpBase      = serverUrl.replace(/\/$/, '')

  // ── Init ────────────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false

    async function init() {
      try {
        await sodiumReady()

        // Restore or generate stable key pair (shared with useE2EChat)
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

  // ── encryptFile ──────────────────────────────────────────────────────────────

  const encryptFile = useCallback(async (file: File | Blob, to: string): Promise<EncryptedFile> => {
    if (!isReady || !keyPairRef.current) {
      throw new Error('useE2EFile is not ready yet. Wait for isReady before calling encryptFile.')
    }

    const name     = file instanceof File ? file.name : 'file'
    const mimeType = file.type || 'application/octet-stream'
    const size     = file.size

    if (size > MAX_FILE_BYTES) {
      throw new InvalidKeyError(
        `File too large: ${size} bytes. Maximum supported size is ${MAX_FILE_BYTES} bytes (50 MB).`
      )
    }

    const peerPub = await fetchPeerKey(to)
    const shared  = await deriveSharedSecret(keyPairRef.current.privateKey, peerPub)

    // Import sodium lazily (already ready from init)
    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready

    const fileBytes  = await readFileBytes(file)
    const nonce      = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const ciphertext = sodium.crypto_secretbox_easy(fileBytes, nonce, shared)

    return { ciphertext, nonce, name, mimeType, size }
  }, [isReady, fetchPeerKey])

  // ── decryptFile ──────────────────────────────────────────────────────────────

  const decryptFile = useCallback(async (encrypted: EncryptedFile, from: string): Promise<File> => {
    if (!keyPairRef.current) {
      throw new Error('useE2EFile is not ready yet. Wait for isReady before calling decryptFile.')
    }

    const peerPub = await fetchPeerKey(from)
    const shared  = await deriveSharedSecret(keyPairRef.current.privateKey, peerPub)

    const { default: sodium } = await import('libsodium-wrappers')
    await sodium.ready

    let plainBytes: Uint8Array | null
    try {
      plainBytes = sodium.crypto_secretbox_open_easy(encrypted.ciphertext, encrypted.nonce, shared)
    } catch {
      throw new DecryptionFailedError('File decryption failed — wrong key or corrupted data.')
    }

    if (!plainBytes) {
      throw new DecryptionFailedError('File decryption failed — authentication check failed.')
    }

    // Slice to a plain ArrayBuffer so TypeScript's BlobPart type is satisfied
    const buf = plainBytes.buffer.slice(
      plainBytes.byteOffset,
      plainBytes.byteOffset + plainBytes.byteLength,
    ) as ArrayBuffer
    return new File([buf], encrypted.name, { type: encrypted.mimeType })
  }, [fetchPeerKey])

  return { encryptFile, decryptFile, isReady, error }
}
