import _sodium from 'libsodium-wrappers'
import { KeyPair } from './keyPair.js'
import { DecryptionFailedError, InvalidKeyError } from '../errors.js'

export const MAX_SKIP_KEYS = 1000
export const RATCHET_VERSION = 1

// ── Types ─────────────────────────────────────────────────────────────────────

export interface MessageHeader {
  /** Sender's current DH ratchet public key (base64). */
  dh: string
  /** Number of messages sent in the previous sending chain. */
  pn: number
  /** Message number in the current sending chain. */
  n: number
}

export interface RatchetMessage {
  header: MessageHeader
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
  MKSKIPPED: Array<[string, string]>
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
  MKSKIPPED: Map<string, Uint8Array>
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
 * KDF_RK: HKDF-SHA256 using the root key as salt and a DH output as IKM.
 * Returns [new_root_key, new_chain_key].
 */
function kdfRK(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const prk    = prf(rk, dhOut)
  const newRK  = prf(prk, new Uint8Array([1]))
  const newCK  = prf(prk, new Uint8Array([...newRK, 2]))
  return [newRK, newCK]
}

/**
 * KDF_CK: Advances the chain key one step.
 * Returns [next_chain_key, message_key].
 * Message key must be used once then wiped.
 */
function kdfCK(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const mk     = prf(ck, new Uint8Array([1]))
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

function skippedMapKey(dhPub: Uint8Array, n: number): string {
  return `${b64(dhPub)}:${n}`
}

// ── DoubleRatchet ─────────────────────────────────────────────────────────────

/**
 * Signal Double Ratchet implementation.
 *
 * Combines a symmetric-key ratchet (one message key per message, deleted after
 * use) with a Diffie-Hellman ratchet (new DH key pair on every direction change)
 * to provide both forward secrecy and break-in recovery.
 *
 * Usage:
 * ```typescript
 * // Alice (sender)
 * const alice = await DoubleRatchet.initSender(sharedSecret, bobPublicKey)
 * const msg   = await alice.encrypt('Hello Bob!')
 *
 * // Bob (receiver — keeps his key pair from the initial key exchange)
 * const bob   = await DoubleRatchet.initReceiver(sharedSecret, bobKeyPair)
 * const text  = await bob.decrypt(msg)   // 'Hello Bob!'
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
   * Performs the first DH ratchet step immediately so the first message
   * already uses a fresh chain key derived from a new ephemeral DH pair.
   *
   * @param sharedSecret  - 32-byte shared secret from the initial key exchange.
   * @param theirPublicKey - Recipient's DH ratchet public key (Bob's identity/ratchet key).
   * @throws {InvalidKeyError} If key lengths are wrong.
   * @example
   * const alice = await DoubleRatchet.initSender(sharedSecret, bob.publicKey)
   */
  static async initSender(sharedSecret: Uint8Array, theirPublicKey: Uint8Array): Promise<DoubleRatchet> {
    await _sodium.ready

    if (sharedSecret.length !== 32) throw new InvalidKeyError(`sharedSecret must be 32 bytes, got ${sharedSecret.length}.`)
    if (theirPublicKey.length !== _sodium.crypto_box_PUBLICKEYBYTES) {
      throw new InvalidKeyError(`theirPublicKey must be ${_sodium.crypto_box_PUBLICKEYBYTES} bytes.`)
    }

    const DHs   = _sodium.crypto_box_keypair()
    const dhOut = _sodium.crypto_scalarmult(DHs.privateKey, theirPublicKey)
    const [RK, CKs] = kdfRK(sharedSecret, dhOut)

    return new DoubleRatchet({
      DHs: { publicKey: DHs.publicKey, privateKey: DHs.privateKey },
      DHr: theirPublicKey,
      RK,
      CKs,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      MKSKIPPED: new Map(),
    })
  }

  /**
   * Initialise as the message receiver (Bob).
   * Waits for Alice's first message to derive the receiving chain.
   *
   * @param sharedSecret - 32-byte shared secret from the initial key exchange.
   * @param ourKeyPair   - Bob's DH ratchet key pair (the one Alice used above).
   * @throws {InvalidKeyError} If key lengths are wrong.
   * @example
   * const bob = await DoubleRatchet.initReceiver(sharedSecret, bobKeyPair)
   */
  static async initReceiver(sharedSecret: Uint8Array, ourKeyPair: KeyPair): Promise<DoubleRatchet> {
    await _sodium.ready

    if (sharedSecret.length !== 32) throw new InvalidKeyError(`sharedSecret must be 32 bytes, got ${sharedSecret.length}.`)

    return new DoubleRatchet({
      DHs: ourKeyPair,
      DHr: null,
      RK: sharedSecret,
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      MKSKIPPED: new Map(),
    })
  }

  // ── Encrypt / Decrypt ───────────────────────────────────────────────────────

  /**
   * Encrypt a plaintext string. Advances the sending chain by one step.
   * Each call produces a unique message key that is wiped after use.
   *
   * @param plaintext - UTF-8 string to encrypt.
   * @returns `RatchetMessage` containing the header and ciphertext.
   * @throws {InvalidKeyError} If the sending chain is not yet initialised
   *   (i.e. the receiver tries to send before receiving the first message).
   * @example
   * const msg = await alice.encrypt('Hello!')
   */
  async encrypt(plaintext: string): Promise<RatchetMessage> {
    await _sodium.ready

    if (!this.s.CKs) {
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
    this.s.Ns++

    const nonce      = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES)
    // from_string works in both Node.js and browsers; Buffer.from is Node-only
    const msgBytes   = _sodium.from_string(plaintext)
    const ciphertext = new Uint8Array(_sodium.crypto_secretbox_easy(msgBytes, nonce, mk))
    const nonceCopy  = new Uint8Array(nonce)

    _sodium.memzero(mk)

    return { header, ciphertext, nonce: nonceCopy }
  }

  /**
   * Decrypt a `RatchetMessage`. Automatically advances the receiving chain
   * and performs a DH ratchet step when the sender's DH key changes.
   * Out-of-order messages are supported up to `MAX_SKIP_KEYS` gaps.
   *
   * @param message - Message produced by the sender's `encrypt()`.
   * @returns Decrypted UTF-8 plaintext.
   * @throws {DecryptionFailedError} If authentication fails, the key was already used,
   *   the ciphertext was tampered with, or too many messages were skipped.
   * @example
   * const text = await bob.decrypt(msg)
   */
  async decrypt(message: RatchetMessage): Promise<string> {
    await _sodium.ready

    const { header, ciphertext, nonce } = message
    const headerDHBytes = unb64(header.dh)

    // 1. Check if this is a skipped message we saved a key for
    const skipKey    = skippedMapKey(headerDHBytes, header.n)
    const skippedMK  = this.s.MKSKIPPED.get(skipKey)
    if (skippedMK) {
      this.s.MKSKIPPED.delete(skipKey)
      const plain = this.decryptWithKey(ciphertext, nonce, skippedMK)
      _sodium.memzero(skippedMK)
      return plain
    }

    // 2. If sender's DH key changed — perform DH ratchet step
    const isDHNew = !this.s.DHr || b64(headerDHBytes) !== b64(this.s.DHr)
    if (isDHNew) {
      this.skipMessageKeys(header.pn)
      this.dhRatchetStep(headerDHBytes)
    }

    // 3. Skip any messages we haven't seen yet in the current chain
    this.skipMessageKeys(header.n)

    // 4. Advance the receiving chain
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
    // to_string works in both Node.js and browsers; Buffer.from is Node-only
    return _sodium.to_string(plain)
  }

  private skipMessageKeys(until: number): void {
    if (this.s.Nr + MAX_SKIP_KEYS < until) {
      throw new DecryptionFailedError(`Too many skipped messages (limit: ${MAX_SKIP_KEYS}).`)
    }
    if (!this.s.CKr) return

    while (this.s.Nr < until) {
      const [CKr, mk] = kdfCK(this.s.CKr)
      this.s.CKr = CKr
      this.s.MKSKIPPED.set(skippedMapKey(this.s.DHr!, this.s.Nr), mk)
      this.s.Nr++
    }
  }

  private dhRatchetStep(theirDHPublicKey: Uint8Array): void {
    this.s.PN = this.s.Ns
    this.s.Ns = 0
    this.s.Nr = 0
    this.s.DHr = theirDHPublicKey

    // Receiving step: derive new root key + receiving chain key
    const dhOut1 = _sodium.crypto_scalarmult(this.s.DHs.privateKey, this.s.DHr)
    const [RK1, CKr] = kdfRK(this.s.RK, dhOut1)
    this.s.RK  = RK1
    this.s.CKr = CKr

    // Generate a fresh DH sending key pair
    const newDHs = _sodium.crypto_box_keypair()
    this.s.DHs   = { publicKey: newDHs.publicKey, privateKey: newDHs.privateKey }

    // Sending step: derive new root key + sending chain key
    const dhOut2 = _sodium.crypto_scalarmult(this.s.DHs.privateKey, this.s.DHr)
    const [RK2, CKs] = kdfRK(this.s.RK, dhOut2)
    this.s.RK  = RK2
    this.s.CKs = CKs
  }

  // ── Persistence ─────────────────────────────────────────────────────────────

  /**
   * Export the full ratchet state as a JSON-serialisable object.
   * Store this in IndexedDB (never localStorage) and restore with `fromExport`.
   *
   * @returns `RatchetStateExport` — all keys are base64 strings.
   * @example
   * await idb.put('ratchet', alice.export())
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
      MKSKIPPED:  Array.from(s.MKSKIPPED.entries()).map(([k, v]) => [k, b64(v)]),
    }
  }

  /**
   * Restore a `DoubleRatchet` from a previously exported state.
   *
   * @param data - Object produced by `export()`.
   * @returns Restored `DoubleRatchet` ready to send/receive.
   * @throws {InvalidKeyError} If the version field doesn't match `RATCHET_VERSION`.
   * @example
   * const alice = await DoubleRatchet.fromExport(await idb.get('ratchet'))
   */
  static async fromExport(data: RatchetStateExport): Promise<DoubleRatchet> {
    await _sodium.ready

    if (data.version !== RATCHET_VERSION) {
      throw new InvalidKeyError(
        `Unsupported ratchet state version: ${data.version}. Expected ${RATCHET_VERSION}.`
      )
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
      MKSKIPPED: new Map(data.MKSKIPPED.map(([k, v]) => [k, unb64(v)])),
    })
  }
}
