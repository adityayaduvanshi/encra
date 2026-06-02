/**
 * Direct unit tests for ratchetStore helpers.
 *
 * jsdom has no IndexedDB implementation — getDB() always rejects immediately.
 * All functions handle this gracefully (try/catch fallbacks), so we can call
 * them directly to cover the function bodies and their catch paths.
 */
import { describe, it, expect } from 'vitest'
import {
  loadGhostMode,
  saveGhostMode,
  getOrCreateDeviceId,
  loadKeyPair,
  saveKeyPair,
  loadRatchet,
  saveRatchet,
  loadMessages,
  saveMessages,
} from '../src/ratchetStore.js'

describe('ratchetStore — IDB-unavailable fallbacks', () => {
  it('loadGhostMode returns false when IDB is unavailable', async () => {
    const val = await loadGhostMode('test-user')
    expect(val).toBe(false)
  })

  it('saveGhostMode resolves without throwing when IDB is unavailable', async () => {
    await expect(saveGhostMode('test-user', true)).resolves.toBeUndefined()
    await expect(saveGhostMode('test-user', false)).resolves.toBeUndefined()
  })

  it('getOrCreateDeviceId returns "default" when IDB is unavailable', async () => {
    const id = await getOrCreateDeviceId('test-user')
    expect(id).toBe('default')
  })

  it('loadKeyPair returns undefined when IDB is unavailable', async () => {
    const kp = await loadKeyPair('test-user')
    expect(kp).toBeUndefined()
  })

  it('saveKeyPair resolves without throwing when IDB is unavailable', async () => {
    await expect(
      saveKeyPair('test-user', { pub: 'pub-key', priv: 'priv-key' })
    ).resolves.toBeUndefined()
  })

  it('loadRatchet returns undefined when IDB is unavailable', async () => {
    const state = await loadRatchet('test-user', 'peer-key')
    expect(state).toBeUndefined()
  })

  it('saveRatchet resolves without throwing when IDB is unavailable', async () => {
    await expect(
      saveRatchet('test-user', 'peer-key', { version: 1 } as never)
    ).resolves.toBeUndefined()
  })

  it('loadMessages returns empty array when IDB is unavailable', async () => {
    const msgs = await loadMessages('test-user')
    expect(Array.isArray(msgs)).toBe(true)
    expect(msgs).toHaveLength(0)
  })

  it('saveMessages resolves without throwing when IDB is unavailable', async () => {
    await expect(saveMessages('test-user', [])).resolves.toBeUndefined()
  })
})
