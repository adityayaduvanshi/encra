import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import type { RatchetStateExport, PreKeyMessage } from '@encra/core'
import {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  exportKey,
} from '@encra/core'

/** Shape of a single persisted chat message. */
export interface StoredMessage {
  from:      string
  text:      string
  timestamp: number
}

/**
 * A persisted presence session: the symmetric presence key (base64) derived
 * from an X3DH session root key, plus — for outbound (initiator) sessions — the
 * X3DH prekey message that lets the peer establish the same session. Receiver
 * sessions omit `prekey`. Persisting this keeps the presence key stable across
 * reloads so the peer doesn't have to re-establish on every page load.
 */
export interface StoredPresenceSession {
  key:     string
  prekey?: PreKeyMessage
}

/**
 * This device's X3DH prekey material (private halves included). Persisted so
 * sessions survive reloads and incoming prekey messages can be answered.
 */
export interface StoredPreKeys {
  /** Ed25519 identity key (base64). */
  identityPub:  string
  identityPriv: string
  /** Current signed prekey: X25519 pair + identity signature over its public key. */
  signedPreKey: { keyId: number; pub: string; priv: string; signature: string }
  /** Unused one-time prekey pool (X25519 pairs). Consumed on inbound sessions. */
  oneTimePreKeys: Array<{ keyId: number; pub: string; priv: string }>
  /** Next one-time prekey id to allocate when replenishing the pool. */
  nextOtpId: number
}

interface EncraSchema extends DBSchema {
  keypairs: {
    key:   string
    value: { pub: string; priv: string }
  }
  ratchets: {
    key:   string
    value: RatchetStateExport
  }
  messages: {
    key:   string        // userId
    value: StoredMessage[]
  }
  devices: {
    key:   string        // userId
    value: string        // deviceId (UUID)
  }
  prekeys: {
    key:   string        // userId
    value: StoredPreKeys
  }
  presence: {
    key:   string        // `${userId}:${dir}:${peerId}:${deviceId}`
    value: StoredPresenceSession
  }
  settings: {
    key:   string        // userId
    value: { ghostMode: boolean }
  }
}

const DB_NAME    = 'encra-v1'
const DB_VERSION = 5

let dbPromise: Promise<IDBPDatabase<EncraSchema>> | null = null

function getDB(): Promise<IDBPDatabase<EncraSchema>> {
  if (typeof window === 'undefined' || !('indexedDB' in window)) {
    return Promise.reject(new Error('IndexedDB unavailable'))
  }
  if (!dbPromise) {
    dbPromise = openDB<EncraSchema>(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains('keypairs')) db.createObjectStore('keypairs')
        if (!db.objectStoreNames.contains('ratchets')) db.createObjectStore('ratchets')
        if (!db.objectStoreNames.contains('messages')) db.createObjectStore('messages')
        if (!db.objectStoreNames.contains('devices'))  db.createObjectStore('devices')
        if (!db.objectStoreNames.contains('prekeys'))  db.createObjectStore('prekeys')
        if (!db.objectStoreNames.contains('presence')) db.createObjectStore('presence')
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings')
      },
    })
  }
  return dbPromise
}

export async function loadKeyPair(userId: string): Promise<{ pub: string; priv: string } | undefined> {
  try {
    return (await getDB()).get('keypairs', userId)
  } catch { return undefined }
}

export async function saveKeyPair(userId: string, kp: { pub: string; priv: string }): Promise<void> {
  try {
    await (await getDB()).put('keypairs', kp, userId)
  } catch { /* non-fatal */ }
}

export async function loadRatchet(userId: string, peerKey: string): Promise<RatchetStateExport | undefined> {
  try {
    return (await getDB()).get('ratchets', `${userId}:${peerKey}`)
  } catch { return undefined }
}

export async function saveRatchet(userId: string, peerKey: string, state: RatchetStateExport): Promise<void> {
  try {
    await (await getDB()).put('ratchets', state, `${userId}:${peerKey}`)
  } catch { /* non-fatal: ratchet still works in-memory */ }
}

export async function loadPreKeys(userId: string): Promise<StoredPreKeys | undefined> {
  try {
    return (await getDB()).get('prekeys', userId)
  } catch { return undefined }
}

export async function savePreKeys(userId: string, prekeys: StoredPreKeys): Promise<void> {
  try {
    await (await getDB()).put('prekeys', prekeys, userId)
  } catch { /* non-fatal: prekeys still held in-memory for this session */ }
}

/** One-time prekey pool size for a freshly generated device. */
const OTP_POOL_SIZE = 100

/**
 * In-flight prekey generation locks, keyed by userId. Guarantees exactly one
 * identity-key + signed-prekey generation per userId per tab, even if multiple
 * `EncraClient` instances (or other callers) initialise prekeys for the same
 * user concurrently. Without this, each caller would generate a *different*
 * identity + signed prekey and race to persist and publish them — leaving this
 * device's stored prekeys out of sync with what peers fetch, which makes the
 * signed-prekey signature fail to verify (a false MITM alarm) and breaks
 * inbound session setup.
 */
const prekeyInits = new Map<string, Promise<{ prekeys: StoredPreKeys; created: boolean }>>()

/**
 * Load this device's prekey material, generating and persisting it on first use.
 * Concurrent callers for the same `userId` share a single generation, so the
 * identity key and signed prekey are always consistent across every consumer.
 *
 * @param userId - The local user whose device prekeys to load or create.
 * @returns The stored prekeys and whether they were freshly created this call
 *   (so the caller can decide whether to publish the full one-time prekey pool).
 * @example
 * const { prekeys, created } = await loadOrCreatePreKeys('alice')
 */
export function loadOrCreatePreKeys(
  userId: string,
): Promise<{ prekeys: StoredPreKeys; created: boolean }> {
  // get → create-promise → set runs with no `await` between, so concurrent
  // callers in the same tab always observe and reuse the first in-flight promise.
  const inFlight = prekeyInits.get(userId)
  if (inFlight) return inFlight

  const promise = (async () => {
    const existing = await loadPreKeys(userId)
    if (existing) return { prekeys: existing, created: false }

    const identity = await generateIdentityKeyPair()
    const spk      = await generateSignedPreKey(identity, 1)
    const otps     = await generateOneTimePreKeys(1, OTP_POOL_SIZE)
    const prekeys: StoredPreKeys = {
      identityPub:  exportKey(identity.publicKey),
      identityPriv: exportKey(identity.privateKey),
      signedPreKey: {
        keyId:     spk.keyId,
        pub:       exportKey(spk.keyPair.publicKey),
        priv:      exportKey(spk.keyPair.privateKey),
        signature: exportKey(spk.signature),
      },
      oneTimePreKeys: otps.map((o) => ({
        keyId: o.keyId,
        pub:   exportKey(o.keyPair.publicKey),
        priv:  exportKey(o.keyPair.privateKey),
      })),
      nextOtpId: OTP_POOL_SIZE + 1,
    }
    await savePreKeys(userId, prekeys)
    return { prekeys, created: true }
  })().finally(() => { prekeyInits.delete(userId) })

  prekeyInits.set(userId, promise)
  return promise
}

export async function loadMessages(userId: string): Promise<StoredMessage[]> {
  try {
    return (await (await getDB()).get('messages', userId)) ?? []
  } catch { return [] }
}

export async function saveMessages(userId: string, messages: StoredMessage[]): Promise<void> {
  try {
    await (await getDB()).put('messages', messages, userId)
  } catch { /* non-fatal: messages still visible in-memory */ }
}

/**
 * Load a persisted presence session by its composite key
 * (`${userId}:${dir}:${peerId}:${deviceId}`), or undefined if none exists.
 */
export async function loadPresenceSession(
  userId: string,
  sessionKey: string,
): Promise<StoredPresenceSession | undefined> {
  try {
    return (await getDB()).get('presence', `${userId}:${sessionKey}`)
  } catch { return undefined }
}

/** Persist a presence session. Best-effort — the in-memory key still works. */
export async function savePresenceSession(
  userId: string,
  sessionKey: string,
  session: StoredPresenceSession,
): Promise<void> {
  try {
    await (await getDB()).put('presence', session, `${userId}:${sessionKey}`)
  } catch { /* non-fatal: presence key still cached in-memory */ }
}

/** Load the persisted ghost-mode flag for a user (defaults to false). */
export async function loadGhostMode(userId: string): Promise<boolean> {
  try {
    return (await (await getDB()).get('settings', userId))?.ghostMode ?? false
  } catch { return false }
}

/** Persist the ghost-mode flag for a user. */
export async function saveGhostMode(userId: string, ghostMode: boolean): Promise<void> {
  try {
    await (await getDB()).put('settings', { ghostMode }, userId)
  } catch { /* non-fatal */ }
}

/**
 * Returns the stable device ID for this browser/device.
 * Generated once with crypto.randomUUID() and persisted to IndexedDB.
 * Falls back to a random string if the Crypto API is unavailable.
 */
export async function getOrCreateDeviceId(userId: string): Promise<string> {
  try {
    const db       = await getDB()
    const existing = await db.get('devices', userId)
    if (existing) return existing

    const deviceId =
      typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`

    await db.put('devices', deviceId, userId)
    return deviceId
  } catch {
    // Fallback for environments where IndexedDB is unavailable (e.g. Node.js tests)
    return 'default'
  }
}
