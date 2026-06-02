import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import type { RatchetStateExport } from '@encra/core'

/** Shape of a single persisted chat message. */
export interface StoredMessage {
  from:      string
  text:      string
  timestamp: number
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
  fieldkeys: {
    key:   string        // userId
    value: string        // base64url symmetric key (32 bytes)
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
        if (!db.objectStoreNames.contains('prekeys'))   db.createObjectStore('prekeys')
        if (!db.objectStoreNames.contains('fieldkeys')) db.createObjectStore('fieldkeys')
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

export async function loadFieldKey(userId: string): Promise<string | undefined> {
  try {
    return (await getDB()).get('fieldkeys', userId)
  } catch { return undefined }
}

export async function saveFieldKey(userId: string, b64: string): Promise<void> {
  try {
    await (await getDB()).put('fieldkeys', b64, userId)
  } catch { /* non-fatal: key still works in-memory */ }
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
    return 'default'
  }
}
