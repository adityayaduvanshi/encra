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

// savePreKeys is a no-op without IndexedDB (jsdom), so these exercise the pure
// retention/rotation logic directly.
describe('signed prekey retention + rotation', () => {
  beforeAll(async () => { await sodiumReady() })

  it('resolves the current signed prekey by id', async () => {
    const pk = await makePrekeys(Date.now())
    const pair = resolveSignedPreKeyPair(pk, 1)
    expect(pair).not.toBeNull()
    expect(pair!.publicKey.length).toBe(32)
    expect(pair!.privateKey.length).toBe(32)
  })

  it('returns null for an unknown signed prekey id', async () => {
    const pk = await makePrekeys(Date.now())
    expect(resolveSignedPreKeyPair(pk, 999)).toBeNull()
  })

  it('does not rotate a fresh signed prekey', async () => {
    const pk = await makePrekeys(Date.now())
    const res = await rotateSignedPreKeyIfStale('u', pk, 60_000)
    expect(res).toBeNull()
    expect(pk.signedPreKey.keyId).toBe(1)
    expect(pk.previousSignedPreKeys).toHaveLength(0)
  })

  it('rotates a stale signed prekey and keeps the old one resolvable', async () => {
    const pk       = await makePrekeys(Date.now())
    const oldKeyId = pk.signedPreKey.keyId
    const oldPub   = pk.signedPreKey.pub

    const res = await rotateSignedPreKeyIfStale('u', pk, 0)  // force rotation
    expect(res).not.toBeNull()
    expect(res!.keyId).toBe(2)
    expect(pk.signedPreKey.keyId).toBe(2)
    expect(pk.signedPreKey.pub).not.toBe(oldPub)
    expect(pk.nextSpkId).toBe(3)

    // The superseded key is retained → a message that referenced it still opens.
    expect(pk.previousSignedPreKeys.map((s) => s.keyId)).toContain(oldKeyId)
    expect(resolveSignedPreKeyPair(pk, oldKeyId)).not.toBeNull()
    expect(resolveSignedPreKeyPair(pk, 2)).not.toBeNull()
  })

  it('caps the retained signed prekeys', async () => {
    const pk = await makePrekeys(Date.now())
    for (let i = 0; i < 6; i++) await rotateSignedPreKeyIfStale('u', pk, 0)
    expect(pk.previousSignedPreKeys.length).toBeLessThanOrEqual(3)
  })
})
