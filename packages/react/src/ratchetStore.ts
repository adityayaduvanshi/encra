import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import type { RatchetStateExport, PreKeyMessage } from '@encra/core'

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
    return 'default'
  }
}
