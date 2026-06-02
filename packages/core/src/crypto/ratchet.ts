import _sodium from 'libsodium-wrappers'
import { KeyPair } from './keyPair.js'
import type { SessionKeys } from './x3dh.js'
import { DecryptionFailedError, InvalidKeyError } from '../errors.js'

export const MAX_SKIP_KEYS = 1000
export const RATCHET_VERSION = 2

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * The ratchet header. With header encryption this never travels in plaintext —
 * it is encrypted under the sending header key and recovered by the receiver.
 */
export interface MessageHeader {
  /** Sender's current DH ratchet public key (base64). */
  dh: string
  /** Number of messages sent in the previous sending chain. */
  pn: number
  /** Message number in the current sending chain. */
  n: number
}

/**
 * An encrypted message on the wire. `encHeader` is the header encrypted under a
 * header key (so the relay can't read the ratchet public key or counters);
 * `ciphertext`/`nonce` are the body encrypted under a per-message key.
 */
export interface RatchetMessage {
  encHeader: Uint8Array
  ciphertext: Uint8Array
  nonce: Uint8Array
}

export interface RatchetStateExport {
  version: number
  DHs_pub: string
  DHs_priv: string
  DHr: string | null
  RK: string
  CKs: string | null
  CKr: string | null
  Ns: number
  Nr: number
  PN: number
  HKs: string | null
  HKr: string | null
  NHKs: string | null
  NHKr: string | null
  /** Skipped message keys: [headerKeyB64, [[n, messageKeyB64], ...]]. */
  MKSKIPPED: Array<[string, Array<[number, string]>]>
}

interface State {
  DHs: KeyPair
  DHr: Uint8Array | null
  RK: Uint8Array
  CKs: Uint8Array | null
  CKr: Uint8Array | null
  Ns: number
  Nr: number
  PN: number
  // Header keys (Double Ratchet with header encryption)
  HKs: Uint8Array | null   // sending header key
  HKr: Uint8Array | null   // receiving header key
  NHKs: Uint8Array | null  // next sending header key
  NHKr: Uint8Array | null  // next receiving header key
  /** Skipped message keys, grouped by the receiving header key they belong to. */
  MKSKIPPED: Map<string, Map<number, Uint8Array>>
}

// ── KDF primitives ────────────────────────────────────────────────────────────

// crypto_auth_hmacsha256 is only in libsodium-wrappers-sumo.
// crypto_generichash (keyed BLAKE2b-256) is available in the standard build
// and is equally sound as a PRF for KDF purposes.
//
// Wrapping in new Uint8Array() defensively copies the output — the browser
// ESM build of libsodium may return a view into WASM heap memory that gets
// overwritten by the next crypto call.
function prf(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(_sodium.crypto_generichash(32, data, key))
}

/**
 * KDF_RK (header-encryption variant): derives a new root key, a chain key, and
 * the next header key from the current root key and a DH output.
 * Returns [new_root_key, chain_key, next_header_key].
 */
function kdfRKHE(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array, Uint8Array] {
  const prk = prf(rk, dhOut)
  const newRK = prf(prk, new Uint8Array([1]))
  const newCK = prf(prk, new Uint8Array([2]))
  const newNHK = prf(prk, new Uint8Array([3]))
  return [newRK, newCK, newNHK]
}

/**
 * KDF_CK: Advances the chain key one step.
 * Returns [next_chain_key, message_key].
 * Message key must be used once then wiped.
 */
function kdfCK(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const mk = prf(ck, new Uint8Array([1]))
  const ckNext = prf(ck, new Uint8Array([2]))
  return [ckNext, mk]
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

function b64(bytes: Uint8Array): string {
  return _sodium.to_base64(bytes, _sodium.base64_variants.URLSAFE_NO_PADDING)
}

function unb64(s: string): Uint8Array {
  return _sodium.from_base64(s, _sodium.base64_variants.URLSAFE_NO_PADDING)
}

// ── Header encryption ───────────────────────────────────────────────────────────

/** Encrypt a header under a header key. Output is `nonce || ciphertext`. */
function encryptHeader(hk: Uint8Array, header: MessageHeader): Uint8Array {
  const nonce = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES)
  // Compact field names keep the encrypted header small.
  const data  = _sodium.from_string(JSON.stringify({ d: header.dh, p: header.pn, n: header.n }))
  const ct    = _sodium.crypto_secretbox_easy(data, nonce, hk)
  const out   = new Uint8Array(nonce.length + ct.length)
  out.set(nonce, 0)
  out.set(ct, nonce.length)
  return out
}

/**
 * Try to decrypt a header with a header key.
 * Returns the header on success, or null if this key doesn't match (so the
 * caller can try the next header key without throwing).
 */
function decryptHeader(hk: Uint8Array, encHeader: Uint8Array): MessageHeader | null {
  const nbytes = _sodium.crypto_secretbox_NONCEBYTES
  if (encHeader.length <= nbytes) return null
  const nonce = encHeader.slice(0, nbytes)
  const ct    = encHeader.slice(nbytes)
  try {
    const data = _sodium.crypto_secretbox_open_easy(ct, nonce, hk)
    if (!data) return null
    const obj = JSON.parse(_sodium.to_string(data)) as { d: string; p: number; n: number }
    if (typeof obj.d !== 'string' || typeof obj.p !== 'number' || typeof obj.n !== 'number') return null
    return { dh: obj.d, pn: obj.p, n: obj.n }
  } catch {
    return null
  }
}

function copy(b: Uint8Array): Uint8Array {
  return new Uint8Array(b)
}

// ── DoubleRatchet ─────────────────────────────────────────────────────────────

/**
 * Signal Double Ratchet with header encryption.
 *
 * Combines a symmetric-key ratchet (one message key per message, deleted after
 * use) with a Diffie-Hellman ratchet (new DH key pair on every direction change)
 * to provide forward secrecy and break-in recovery. In addition, every message
 * header (the ratchet public key and message counters) is encrypted under a
 * per-direction header key, so a relay never sees ratchet metadata.
 *
 * Seed the session with the `SessionKeys` produced by X3DH:
 * ```typescript
 * // Alice (initiator)
 * const init  = await x3dhInitiate(myIdentity, bobBundle)
 * const alice = await DoubleRatchet.initSender(init.sessionKeys, init.signedPreKeyPublic)
 *
 * // Bob (responder)
 * const keys = await x3dhRespond(bobIdentity, bobSpk, bobOtp, init.message)
 * const bob  = await DoubleRatchet.initReceiver(keys, bobSpkKeyPair)
 * ```
 */
export class DoubleRatchet {
  private s: State

  private constructor(state: State) {
    this.s = state
  }

  // ── Initialisation ──────────────────────────────────────────────────────────

  /**
   * Initialise as the message sender (Alice).
   * Performs the first DH ratchet step immediately so the first message already
   * uses a fresh chain key derived from a new ephemeral DH pair.
   *
   * @param keys           - Session keys from `x3dhInitiate` (root + header keys).
   * @param theirPublicKey - Recipient's signed-prekey public key (initial DHr).
   * @throws {InvalidKeyError} If key lengths are wrong.
   */
  static async initSender(keys: SessionKeys, theirPublicKey: Uint8Array): Promise<DoubleRatchet> {
    await _sodium.ready

    validateSessionKeys(keys)
    if (theirPublicKey.length !== _sodium.crypto_box_PUBLICKEYBYTES) {
      throw new InvalidKeyError(`theirPublicKey must be ${_sodium.crypto_box_PUBLICKEYBYTES} bytes.`)
    }

    const DHs   = _sodium.crypto_box_keypair()
    const dhOut = _sodium.crypto_scalarmult(DHs.privateKey, theirPublicKey)
    const [RK, CKs, NHKs] = kdfRKHE(keys.rootKey, dhOut)

    return new DoubleRatchet({
      DHs: { publicKey: DHs.publicKey, privateKey: DHs.privateKey },
      DHr: copy(theirPublicKey),
      RK,
      CKs,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      HKs: copy(keys.headerKey),
      HKr: null,
      NHKs,
      NHKr: copy(keys.nextHeaderKey),
      MKSKIPPED: new Map(),
    })
  }

  /**
   * Initialise as the message receiver (Bob).
   * Waits for Alice's first message to derive the receiving chain.
   *
   * @param keys       - Session keys from `x3dhRespond` (root + header keys).
   * @param ourKeyPair - Our signed-prekey key pair (the initial DH ratchet key).
   * @throws {InvalidKeyError} If key lengths are wrong.
   */
  static async initReceiver(keys: SessionKeys, ourKeyPair: KeyPair): Promise<DoubleRatchet> {
    await _sodium.ready

    validateSessionKeys(keys)

    return new DoubleRatchet({
      DHs: ourKeyPair,
      DHr: null,
      RK: copy(keys.rootKey),
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      HKs: null,
      HKr: null,
      NHKs: copy(keys.nextHeaderKey),
      NHKr: copy(keys.headerKey),
      MKSKIPPED: new Map(),
    })
  }

  // ── Encrypt / Decrypt ───────────────────────────────────────────────────────

  /**
   * Encrypt a plaintext string. Advances the sending chain by one step and
   * encrypts the header under the sending header key.
   *
   * @throws {InvalidKeyError} If the sending chain is not yet initialised.
   */
  async encrypt(plaintext: string): Promise<RatchetMessage> {
    await _sodium.ready

    if (!this.s.CKs || !this.s.HKs) {
      throw new InvalidKeyError(
        'Sending chain not initialised. The receiver must decrypt at least one message before sending.'
      )
    }

    const [CKs, mk] = kdfCK(this.s.CKs)
    this.s.CKs = CKs

    const header: MessageHeader = {
      dh: b64(this.s.DHs.publicKey),
      pn: this.s.PN,
      n: this.s.Ns,
    }
    const encHeader = encryptHeader(this.s.HKs, header)
    this.s.Ns++

    const nonce      = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES)
    const msgBytes   = _sodium.from_string(plaintext)
    const ciphertext = new Uint8Array(_sodium.crypto_secretbox_easy(msgBytes, nonce, mk))
    const nonceCopy  = new Uint8Array(nonce)

    _sodium.memzero(mk)

    return { encHeader, ciphertext, nonce: nonceCopy }
  }

  /**
   * Decrypt a `RatchetMessage`. Recovers the header by trying the receiving
   * header key (and the next one, which signals a DH ratchet step), advances
   * the receiving chain, and tolerates out-of-order messages up to
   * `MAX_SKIP_KEYS` gaps.
   *
   * @throws {DecryptionFailedError} If the header can't be decrypted with any
   *   known header key, authentication fails, the key was already used, or too
   *   many messages were skipped.
   */
  async decrypt(message: RatchetMessage): Promise<string> {
    await _sodium.ready

    const { encHeader, ciphertext, nonce } = message

    // 1. Check skipped message keys (try each stored header key on the header).
    const skipped = this.trySkippedMessageKeys(encHeader, ciphertext, nonce)
    if (skipped !== null) return skipped

    // 2. Decrypt the header. HKr → current chain; NHKr → a DH ratchet step.
    const { header, dhRatchet } = this.decryptHeaderWithRatchetFlag(encHeader)

    if (dhRatchet) {
      this.skipMessageKeys(header.pn)
      this.dhRatchetStep(header)
    }

    // 3. Skip any messages we haven't seen yet in the current chain.
    this.skipMessageKeys(header.n)

    // 4. Advance the receiving chain.
    const [CKr, mk] = kdfCK(this.s.CKr!)
    this.s.CKr = CKr
    this.s.Nr++

    const plain = this.decryptWithKey(ciphertext, nonce, mk)
    _sodium.memzero(mk)
    return plain
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private decryptWithKey(ciphertext: Uint8Array, nonce: Uint8Array, mk: Uint8Array): string {
    let plain: Uint8Array | null
    try {
      plain = _sodium.crypto_secretbox_open_easy(ciphertext, nonce, mk)
    } catch {
      throw new DecryptionFailedError()
    }
    if (!plain) throw new DecryptionFailedError()
    return _sodium.to_string(plain)
  }

  /**
   * Decrypt the header, returning whether it implies a DH ratchet step.
   * Tries the current receiving header key first, then the next one.
   */
  private decryptHeaderWithRatchetFlag(encHeader: Uint8Array): { header: MessageHeader; dhRatchet: boolean } {
    if (this.s.HKr) {
      const h = decryptHeader(this.s.HKr, encHeader)
      if (h) return { header: h, dhRatchet: false }
    }
    if (this.s.NHKr) {
      const h = decryptHeader(this.s.NHKr, encHeader)
      if (h) return { header: h, dhRatchet: true }
    }
    throw new DecryptionFailedError('Header could not be decrypted with any known header key.')
  }

  /**
   * Try to decrypt the message using a previously skipped message key.
   * Each stored header key is tried against the encrypted header; if one
   * decrypts it and a message key for that counter is held, it is consumed.
   */
  private trySkippedMessageKeys(
    encHeader: Uint8Array,
    ciphertext: Uint8Array,
    nonce: Uint8Array,
  ): string | null {
    for (const [hkB64, inner] of this.s.MKSKIPPED) {
      const hk = unb64(hkB64)
      const header = decryptHeader(hk, encHeader)
      if (!header) continue

      const mk = inner.get(header.n)
      if (!mk) {
        // Header matches this chain but no skipped key for this counter — it's a
        // normal in-order message; let the main path handle it.
        return null
      }
      inner.delete(header.n)
      if (inner.size === 0) this.s.MKSKIPPED.delete(hkB64)

      const plain = this.decryptWithKey(ciphertext, nonce, mk)
      _sodium.memzero(mk)
      return plain
    }
    return null
  }

  private skipMessageKeys(until: number): void {
    if (this.s.Nr + MAX_SKIP_KEYS < until) {
      throw new DecryptionFailedError(`Too many skipped messages (limit: ${MAX_SKIP_KEYS}).`)
    }
    if (!this.s.CKr || !this.s.HKr) return

    const hkB64 = b64(this.s.HKr)
    let inner = this.s.MKSKIPPED.get(hkB64)
    while (this.s.Nr < until) {
      const [CKr, mk] = kdfCK(this.s.CKr)
      this.s.CKr = CKr
      if (!inner) {
        inner = new Map()
        this.s.MKSKIPPED.set(hkB64, inner)
      }
      inner.set(this.s.Nr, mk)
      this.s.Nr++
    }
  }

  private dhRatchetStep(header: MessageHeader): void {
    this.s.PN = this.s.Ns
    this.s.Ns = 0
    this.s.Nr = 0
    this.s.HKs = this.s.NHKs
    this.s.HKr = this.s.NHKr
    this.s.DHr = unb64(header.dh)

    // Receiving step: derive new root key, receiving chain key, next receiving header key
    const dhOut1 = _sodium.crypto_scalarmult(this.s.DHs.privateKey, this.s.DHr)
    const [RK1, CKr, NHKr] = kdfRKHE(this.s.RK, dhOut1)
    this.s.RK   = RK1
    this.s.CKr  = CKr
    this.s.NHKr = NHKr

    // Generate a fresh DH sending key pair
    const newDHs = _sodium.crypto_box_keypair()
    this.s.DHs   = { publicKey: newDHs.publicKey, privateKey: newDHs.privateKey }

    // Sending step: derive new root key, sending chain key, next sending header key
    const dhOut2 = _sodium.crypto_scalarmult(this.s.DHs.privateKey, this.s.DHr)
    const [RK2, CKs, NHKs] = kdfRKHE(this.s.RK, dhOut2)
    this.s.RK   = RK2
    this.s.CKs  = CKs
    this.s.NHKs = NHKs
  }

  // ── Persistence ─────────────────────────────────────────────────────────────

  /**
   * Export the full ratchet state as a JSON-serialisable object.
   * Store this in IndexedDB (never localStorage) and restore with `fromExport`.
   */
  export(): RatchetStateExport {
    const s = this.s
    return {
      version:    RATCHET_VERSION,
      DHs_pub:    b64(s.DHs.publicKey),
      DHs_priv:   b64(s.DHs.privateKey),
      DHr:        s.DHr  ? b64(s.DHr)  : null,
      RK:         b64(s.RK),
      CKs:        s.CKs  ? b64(s.CKs)  : null,
      CKr:        s.CKr  ? b64(s.CKr)  : null,
      Ns:         s.Ns,
      Nr:         s.Nr,
      PN:         s.PN,
      HKs:        s.HKs  ? b64(s.HKs)  : null,
      HKr:        s.HKr  ? b64(s.HKr)  : null,
      NHKs:       s.NHKs ? b64(s.NHKs) : null,
      NHKr:       s.NHKr ? b64(s.NHKr) : null,
      MKSKIPPED:  Array.from(s.MKSKIPPED.entries()).map(([hk, inner]) => [
        hk,
        Array.from(inner.entries()).map(([n, mk]) => [n, b64(mk)] as [number, string]),
      ]),
    }
  }

  /**
   * Restore a `DoubleRatchet` from a previously exported state.
   *
   * @throws {InvalidKeyError} If the version field doesn't match `RATCHET_VERSION`.
   */
  static async fromExport(data: RatchetStateExport): Promise<DoubleRatchet> {
    await _sodium.ready

    if (data.version !== RATCHET_VERSION) {
      throw new InvalidKeyError(
        `Unsupported ratchet state version: ${data.version}. Expected ${RATCHET_VERSION}.`
      )
    }

    const mkskipped = new Map<string, Map<number, Uint8Array>>()
    for (const [hk, inner] of data.MKSKIPPED) {
      mkskipped.set(hk, new Map(inner.map(([n, mk]) => [n, unb64(mk)])))
    }

    return new DoubleRatchet({
      DHs: { publicKey: unb64(data.DHs_pub), privateKey: unb64(data.DHs_priv) },
      DHr:  data.DHr  ? unb64(data.DHr)  : null,
      RK:   unb64(data.RK),
      CKs:  data.CKs  ? unb64(data.CKs)  : null,
      CKr:  data.CKr  ? unb64(data.CKr)  : null,
      Ns:   data.Ns,
      Nr:   data.Nr,
      PN:   data.PN,
      HKs:  data.HKs  ? unb64(data.HKs)  : null,
      HKr:  data.HKr  ? unb64(data.HKr)  : null,
      NHKs: data.NHKs ? unb64(data.NHKs) : null,
      NHKr: data.NHKr ? unb64(data.NHKr) : null,
      MKSKIPPED: mkskipped,
    })
  }
}

function validateSessionKeys(keys: SessionKeys): void {
  if (keys.rootKey.length !== 32) throw new InvalidKeyError(`rootKey must be 32 bytes, got ${keys.rootKey.length}.`)
  if (keys.headerKey.length !== 32) throw new InvalidKeyError(`headerKey must be 32 bytes, got ${keys.headerKey.length}.`)
  if (keys.nextHeaderKey.length !== 32) throw new InvalidKeyError(`nextHeaderKey must be 32 bytes, got ${keys.nextHeaderKey.length}.`)
}
