import { describe, it, expect, beforeAll } from 'vitest'
import {
  sodiumReady,
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  exportKey,
} from '@encra/core'
import {
  resolveSignedPreKeyPair,
  rotateSignedPreKeyIfStale,
  loadOrCreateStorageRootKey,
  type StoredPreKeys,
} from '../src/ratchetStore.js'

async function makePrekeys(createdAt: number): Promise<StoredPreKeys> {
  const identity = await generateIdentityKeyPair()
  const spk      = await generateSignedPreKey(identity, 1)
  const [otp]    = await generateOneTimePreKeys(1, 1)
  return {
    identityPub:  exportKey(identity.publicKey),
    identityPriv: exportKey(identity.privateKey),
    signedPreKey: {
      keyId: 1,
      pub: exportKey(spk.keyPair.publicKey),
      priv: exportKey(spk.keyPair.privateKey),
      signature: exportKey(spk.signature),
    },
    signedPreKeyCreatedAt: createdAt,
    previousSignedPreKeys: [],
    nextSpkId: 2,
    oneTimePreKeys: [{
      keyId: otp!.keyId,
      pub: exportKey(otp!.keyPair.publicKey),
      priv: exportKey(otp!.keyPair.privateKey),
    }],
    nextOtpId: 2,
  }
}

describe('signed prekey retention + rotation', () => {
  beforeAll(async () => { await sodiumReady() })

  it('resolves current and returns null for unknown ids', async () => {
    const pk = await makePrekeys(Date.now())
    expect(resolveSignedPreKeyPair(pk, 1)).not.toBeNull()
    expect(resolveSignedPreKeyPair(pk, 42)).toBeNull()
  })

  it('does not rotate a fresh signed prekey', async () => {
    const pk = await makePrekeys(Date.now())
    expect(await rotateSignedPreKeyIfStale('u', pk, 60_000)).toBeNull()
    expect(pk.signedPreKey.keyId).toBe(1)
  })

  it('rotates a stale signed prekey and keeps the old one resolvable', async () => {
    const pk       = await makePrekeys(Date.now())
    const oldKeyId = pk.signedPreKey.keyId
    const oldPub   = pk.signedPreKey.pub

    const res = await rotateSignedPreKeyIfStale('u', pk, 0)
    expect(res!.keyId).toBe(2)
    expect(pk.signedPreKey.keyId).toBe(2)
    expect(pk.signedPreKey.pub).not.toBe(oldPub)
    expect(pk.previousSignedPreKeys.map((s) => s.keyId)).toContain(oldKeyId)
    expect(resolveSignedPreKeyPair(pk, oldKeyId)).not.toBeNull()
    expect(resolveSignedPreKeyPair(pk, 2)).not.toBeNull()
  })

  it('caps the retained signed prekeys', async () => {
    const pk = await makePrekeys(Date.now())
    for (let i = 0; i < 6; i++) await rotateSignedPreKeyIfStale('u', pk, 0)
    expect(pk.previousSignedPreKeys.length).toBeLessThanOrEqual(3)
  })

  it('loadOrCreateStorageRootKey returns one stable key under concurrent first use', async () => {
    const hex = (k: Uint8Array) => Array.from(k).join(',')
    const keys = await Promise.all(Array.from({ length: 12 }, () => loadOrCreateStorageRootKey('concurrent-user-c')))
    const first = hex(keys[0]!)
    for (const k of keys) expect(hex(k)).toBe(first)
    expect(hex(await loadOrCreateStorageRootKey('concurrent-user-c'))).toBe(first)
  })
})
