import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import type { RatchetStateExport, PreKeyMessage, KeyPair, IdentityKeyPair } from '@encra/core'
import {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  exportKey,
  importKey,
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

/** A stored signed prekey: X25519 pair + the identity signature over its public key. */
export interface StoredSignedPreKey {
  keyId: number; pub: string; priv: string; signature: string
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
  signedPreKey: StoredSignedPreKey
  /**
   * When the current signed prekey was generated (ms epoch). Drives rotation —
   * a signed prekey older than {@link SIGNED_PREKEY_MAX_AGE_MS} is rotated.
   */
  signedPreKeyCreatedAt: number
  /**
   * Previously-current signed prekeys, retained (capped) so this device can
   * still answer prekey messages that referenced an older signed prekey — e.g.
   * a message that was in flight or queued offline across a rotation. Without
   * this, rotating the signed prekey would make those sessions undecryptable.
   */
  previousSignedPreKeys: StoredSignedPreKey[]
  /** Next signed-prekey id to allocate on rotation. */
  nextSpkId: number
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

/** How many superseded signed prekeys to retain for rotation safety. */
const MAX_RETAINED_SIGNED_PREKEYS = 3

/**
 * Rotate the signed prekey once it is older than this. Rotation gives sessions
 * forward secrecy at signed-prekey granularity; retention (see
 * {@link StoredPreKeys.previousSignedPreKeys}) keeps the rotation lossless.
 */
export const SIGNED_PREKEY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000  // 7 days

/**
 * Resolve the signed-prekey key pair a prekey message refers to, searching the
 * current signed prekey and the retained previous ones. Returns null if the id
 * matches none (the key is truly gone — the session cannot be established).
 *
 * @param prekeys - This device's stored prekey material.
 * @param keyId   - `signedPreKeyId` from the inbound prekey message.
 */
export function resolveSignedPreKeyPair(prekeys: StoredPreKeys, keyId: number): KeyPair | null {
  const candidates = [prekeys.signedPreKey, ...(prekeys.previousSignedPreKeys ?? [])]
  const found = candidates.find((s) => s.keyId === keyId)
  if (!found) return null
  return { publicKey: importKey(found.pub), privateKey: importKey(found.priv) }
}

/**
 * Rotate the signed prekey if the current one is older than `maxAgeMs`. A fresh
 * signed prekey is generated and signed by the identity key; the outgoing one is
 * moved into the retained list (capped at {@link MAX_RETAINED_SIGNED_PREKEYS}) so
 * in-flight messages against it still open. Persists the updated material.
 *
 * @returns The new public signed-prekey material to publish, or null if no
 *   rotation was due (nothing to publish).
 */
export async function rotateSignedPreKeyIfStale(
  userId: string,
  prekeys: StoredPreKeys,
  maxAgeMs: number = SIGNED_PREKEY_MAX_AGE_MS,
): Promise<{ keyId: number; publicKey: string; signature: string } | null> {
  if (Date.now() - prekeys.signedPreKeyCreatedAt < maxAgeMs) return null

  const identity: IdentityKeyPair = {
    publicKey:  importKey(prekeys.identityPub),
    privateKey: importKey(prekeys.identityPriv),
  }
  const spk = await generateSignedPreKey(identity, prekeys.nextSpkId)

  // Retain the outgoing current signed prekey (newest-first, capped).
  prekeys.previousSignedPreKeys = [prekeys.signedPreKey, ...(prekeys.previousSignedPreKeys ?? [])]
    .slice(0, MAX_RETAINED_SIGNED_PREKEYS)
  prekeys.signedPreKey = {
    keyId:     spk.keyId,
    pub:       exportKey(spk.keyPair.publicKey),
    priv:      exportKey(spk.keyPair.privateKey),
    signature: exportKey(spk.signature),
  }
  prekeys.signedPreKeyCreatedAt = Date.now()
  prekeys.nextSpkId += 1
  await savePreKeys(userId, prekeys)

  return { keyId: spk.keyId, publicKey: prekeys.signedPreKey.pub, signature: prekeys.signedPreKey.signature }
}

/**
 * In-flight prekey generation locks, keyed by userId. `useE2EChat` and
 * `useE2EPresence` both initialise prekeys on mount for the same userId. Without
 * a shared lock they would each independently generate a *different* identity
 * key + signed prekey and race to persist and publish them — leaving this
 * device's stored prekeys out of sync with what peers fetch from the server.
 * That mismatch makes the signed-prekey signature fail to verify on the
 * initiator side (a false MITM alarm) and breaks inbound session setup on the
 * responder side. This map guarantees exactly one generation per userId per tab.
 */
const prekeyInits = new Map<string, Promise<{ prekeys: StoredPreKeys; created: boolean }>>()

/**
 * Load this device's prekey material, generating and persisting it on first use.
 * Concurrent callers for the same `userId` share a single generation, so the
 * identity key and signed prekey are always consistent across every hook that
 * uses them.
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
    if (existing) {
      // Backfill rotation fields for prekeys saved before retention existed, so
      // older installs upgrade in place without regenerating their identity.
      let changed = false
      if (existing.signedPreKeyCreatedAt === undefined) { existing.signedPreKeyCreatedAt = Date.now(); changed = true }
      if (existing.previousSignedPreKeys  === undefined) { existing.previousSignedPreKeys  = [];         changed = true }
      if (existing.nextSpkId              === undefined) { existing.nextSpkId              = existing.signedPreKey.keyId + 1; changed = true }
      if (changed) await savePreKeys(userId, existing)
      return { prekeys: existing, created: false }
    }

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
      signedPreKeyCreatedAt: Date.now(),
      previousSignedPreKeys: [],
      nextSpkId:             spk.keyId + 1,
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
    return 'default'
  }
}
