import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import type { RatchetStateExport, PreKeyMessage, KeyPair, IdentityKeyPair } from '@encra/core'
import {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  generateStorageRootKey,
  exportKey,
  importKey,
} from '@encra/core'

/** Shape of a single persisted chat message. (id/to/conversationId optional for
 *  back-compat with records written before conversation support.) */
export interface StoredMessage {
  id?:             string
  conversationId?: string
  from:            string
  to?:             string
  text:            string
  timestamp:       number
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

/** A queued outbound message awaiting delivery (persisted so it survives reloads). */
export interface StoredOutboxItem {
  /** The userId that owns this queued send (so one store can hold many users). */
  userId: string
  /** Stable message id (shared with the rendered Message). */
  id:     string
  /** Recipient userId. */
  to:     string
  text:   string
  /** Sender's send time (ms epoch). */
  ts:     number
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
  storagekeys: {
    key:   string        // userId
    value: string        // base64 at-rest storage root key
  }
  outbox: {
    key:   string        // `${userId}:${messageId}`
    value: StoredOutboxItem
  }
  identities: {
    key:   string        // `${userId}:${peerId}:${deviceId}`
    value: string        // base64 Ed25519 identity public key pinned on first contact
  }
}

const DB_NAME    = 'encra-v1'
const DB_VERSION = 8

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
        if (!db.objectStoreNames.contains('storagekeys')) db.createObjectStore('storagekeys')
        if (!db.objectStoreNames.contains('outbox')) db.createObjectStore('outbox')
        if (!db.objectStoreNames.contains('identities')) db.createObjectStore('identities')
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

/** Delete a stored ratchet so the next message re-establishes the session. */
export async function deleteRatchet(userId: string, peerKey: string): Promise<void> {
  try { await (await getDB()).delete('ratchets', `${userId}:${peerKey}`) } catch { /* non-fatal */ }
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
    // Fallback for environments where IndexedDB is unavailable (e.g. Node.js tests)
    return 'default'
  }
}

/** In-session cache so repeated calls return the same key even without IndexedDB. */
const storageKeyCache = new Map<string, Uint8Array>()
/**
 * In-flight generation locks, keyed by userId. Without this, a burst of messages
 * persisted on first use would each find no stored key, each generate a DIFFERENT
 * one, and race to persist (last wins) — leaving some records encrypted under a
 * key that is no longer the stored one, so they fail to decrypt after a reload.
 * The lock makes concurrent callers share exactly one generation.
 */
const storageKeyInits = new Map<string, Promise<Uint8Array>>()

/**
 * Load (or create and persist) this user's at-rest storage root key — the
 * long-lived key behind `encryptForStorage`/`decryptFromStorage`. Held only on
 * this device; never sent to any server. If IndexedDB is unavailable it falls
 * back to an in-session key (history won't survive a reload, but the primitives
 * still work).
 */
export function loadOrCreateStorageRootKey(userId: string): Promise<Uint8Array> {
  const cached = storageKeyCache.get(userId)
  if (cached) return Promise.resolve(cached)
  // get → create-promise → set with no `await` between, so concurrent callers
  // always observe and reuse the first in-flight generation.
  const inFlight = storageKeyInits.get(userId)
  if (inFlight) return inFlight

  const promise = (async () => {
    let key: Uint8Array
    try {
      const db       = await getDB()
      const existing = await db.get('storagekeys', userId)
      if (existing) {
        key = importKey(existing)
      } else {
        key = await generateStorageRootKey()
        await db.put('storagekeys', exportKey(key), userId)
      }
    } catch {
      key = await generateStorageRootKey()
    }
    storageKeyCache.set(userId, key)
    return key
  })().finally(() => { storageKeyInits.delete(userId) })

  storageKeyInits.set(userId, promise)
  return promise
}

// ── Outbound queue (persisted; flushed on reconnect) ──────────────────────────

/** In-memory fallback when IndexedDB is unavailable, so the outbox still works
 *  for the session (it just won't survive a reload). Key: `${userId}:${id}`. */
const memOutbox = new Map<string, StoredOutboxItem>()

/** Queue an outbound message for (re)delivery. Keyed by id, so enqueue is atomic
 *  and race-free (no read-modify-write of a shared array). */
export async function enqueueOutbox(item: StoredOutboxItem): Promise<void> {
  try { await (await getDB()).put('outbox', item, `${item.userId}:${item.id}`) }
  catch { memOutbox.set(`${item.userId}:${item.id}`, item) }
}

/** All queued sends for a user, oldest-first. */
export async function loadOutbox(userId: string): Promise<StoredOutboxItem[]> {
  try {
    const all = await (await getDB()).getAll('outbox')
    return all.filter((o) => o.userId === userId).sort((a, b) => a.ts - b.ts)
  } catch {
    return [...memOutbox.values()].filter((o) => o.userId === userId).sort((a, b) => a.ts - b.ts)
  }
}

/** Remove a delivered message from the queue. */
export async function removeOutbox(userId: string, id: string): Promise<void> {
  try { await (await getDB()).delete('outbox', `${userId}:${id}`) }
  catch { memOutbox.delete(`${userId}:${id}`) }
}

// ── Pinned peer identities (trust-on-first-use + change detection) ─────────────

/** In-memory fallback (and in-session detection) when IndexedDB is unavailable. */
const memIdentities = new Map<string, string>()

/** The identity key we first saw (and trusted) for a peer device, or undefined. */
export async function loadPinnedIdentity(userId: string, peerId: string, deviceId: string): Promise<string | undefined> {
  const key = `${userId}:${peerId}:${deviceId}`
  try { return (await getDB()).get('identities', key) } catch { return memIdentities.get(key) }
}

/** Pin (or re-pin) the identity key for a peer device. */
export async function pinIdentity(userId: string, peerId: string, deviceId: string, identityKey: string): Promise<void> {
  const key = `${userId}:${peerId}:${deviceId}`
  try { await (await getDB()).put('identities', identityKey, key) } catch { memIdentities.set(key, identityKey) }
}
