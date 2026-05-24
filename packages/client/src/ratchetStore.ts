import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import type { RatchetStateExport } from '@encra/core'

/** Shape of a single persisted chat message. */
export interface StoredMessage {
  from:      string
  text:      string
  timestamp: number
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
}

const DB_NAME    = 'encra-v1'
const DB_VERSION = 2

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
