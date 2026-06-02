import _sodium from 'libsodium-wrappers'
import { KeyPair } from './keyPair.js'
import {
  IdentityKeyPair,
  sign,
  verify,
  identityPublicToX25519,
  identityPrivateToX25519,
} from './identity.js'
import { InvalidKeyError, DecryptionFailedError } from '../errors.js'

// ── Constants ───────────────────────────────────────────────────────────────

/**
 * Domain-separation label used as the BLAKE2b key when deriving the X3DH
 * shared secret. Bumping this string invalidates all in-flight handshakes.
 */
const X3DH_KDF_INFO = 'Encra_X3DH_v1'

// ── Types ───────────────────────────────────────────────────────────────────

/**
 * A signed prekey: a medium-term X25519 key pair whose public half is signed
 * by the owner's identity key. Rotated periodically (e.g. weekly). The
 * signature lets an initiator confirm the prekey really came from the claimed
 * identity and was not substituted by the server.
 */
export interface SignedPreKey {
  /** Monotonic id so the owner can find the matching private key later. */
  keyId: number
  /** X25519 key pair. */
  keyPair: KeyPair
  /** Ed25519 signature over `keyPair.publicKey`, made by the identity key. */
  signature: Uint8Array
}

/**
 * A one-time prekey: a single-use X25519 key pair. The server hands out one per
 * session initiation and deletes it, giving the very first message forward
 * secrecy even before the Double Ratchet's first DH step.
 */
export interface OneTimePreKey {
  keyId: number
  keyPair: KeyPair
}

/**
 * The public prekey bundle published to the key server and fetched by an
 * initiator. Contains only public material — never private keys.
 */
export interface PreKeyBundle {
  /** Ed25519 identity public key (base64). */
  identityKey: string
  signedPreKey: {
    keyId: number
    /** X25519 public key (base64). */
    publicKey: string
    /** Ed25519 signature over the signed-prekey public key (base64). */
    signature: string
  }
  /** Present only if the server still has unused one-time prekeys. */
  oneTimePreKey?: {
    keyId: number
    /** X25519 public key (base64). */
    publicKey: string
  }
}

/**
 * The symmetric key material an X3DH handshake produces. Both parties derive an
 * identical `SessionKeys` and feed it into the header-encrypted Double Ratchet.
 *
 * The Double Ratchet with header encryption needs, besides the root key, two
 * additional shared secrets to seed the header keys for each direction (the
 * X3DH spec calls these `shared_hka` and `shared_nhkb`).
 */
export interface SessionKeys {
  /** Root key (SK) — seeds the Double Ratchet root chain. */
  rootKey: Uint8Array
  /** Initiator's first sending header key (`shared_hka`). */
  headerKey: Uint8Array
  /** Responder's first sending header key (`shared_nhkb`). */
  nextHeaderKey: Uint8Array
}

/**
 * The result of a sender-side X3DH handshake.
 *
 * `sessionKeys` seeds the Double Ratchet
 * (`initSender(sessionKeys, signedPreKeyPublic)`). The remaining fields make up
 * the prekey message the initiator sends alongside the first ciphertext so the
 * recipient can derive the same keys.
 */
export interface X3DHInitiation {
  /** Root + header key material. Feed into `DoubleRatchet.initSender`. */
  sessionKeys: SessionKeys
  /**
   * The recipient's signed-prekey public key (raw). Used as the initial DH
   * ratchet key when seeding the Double Ratchet.
   */
  signedPreKeyPublic: Uint8Array
  /** The prekey message to transmit with the first ciphertext. */
  message: PreKeyMessage
}

/**
 * The prekey message an initiator sends with their first ciphertext. Carries
 * the public keys the recipient needs to reconstruct the X3DH shared secret.
 */
export interface PreKeyMessage {
  /** Initiator's Ed25519 identity public key (base64). */
  identityKey: string
  /** Initiator's ephemeral X25519 public key (base64). */
  ephemeralKey: string
  /** Which of the recipient's signed prekeys was used. */
  signedPreKeyId: number
  /** Which of the recipient's one-time prekeys was used, or null if none. */
  oneTimePreKeyId: number | null
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

function b64(bytes: Uint8Array): string {
  return _sodium.to_base64(bytes, _sodium.base64_variants.URLSAFE_NO_PADDING)
}

function unb64(s: string): Uint8Array {
  return _sodium.from_base64(s, _sodium.base64_variants.URLSAFE_NO_PADDING)
}

// ── KDF ─────────────────────────────────────────────────────────────────────

/**
 * Derives the 32-byte X3DH shared secret from the concatenated DH outputs.
 *
 * Per the X3DH spec, the input is prefixed with 32 0xFF bytes (the curve's
 * domain-separation prefix for Curve25519). We use keyed BLAKE2b-256 as the
 * PRF, matching the Double Ratchet's KDF choice (the standard libsodium build
 * has no HKDF-SHA256, and keyed BLAKE2b is an equally sound PRF here).
 */
function x3dhKDF(dhConcat: Uint8Array, domain: number): Uint8Array {
  // Per the X3DH spec the input is prefixed with 32 0xFF bytes (Curve25519
  // domain-separation prefix). We additionally prepend a one-byte domain label
  // (so we can derive several independent keys from one handshake) plus a
  // versioned info string, folding them into the hashed message rather than
  // using a BLAKE2b key (which has length constraints).
  const F     = new Uint8Array(32).fill(0xff)
  const label = _sodium.from_string(X3DH_KDF_INFO)
  const input = new Uint8Array(1 + F.length + label.length + dhConcat.length)
  input[0] = domain
  input.set(F, 1)
  input.set(label, 1 + F.length)
  input.set(dhConcat, 1 + F.length + label.length)
  return new Uint8Array(_sodium.crypto_generichash(32, input))
}

/**
 * Derives the full session key material (root key + the two header-key secrets
 * the header-encrypted ratchet needs) from the concatenated DH outputs. Both
 * parties run this over identical input and get identical keys.
 */
function deriveSessionKeys(dhConcat: Uint8Array): SessionKeys {
  return {
    rootKey:       x3dhKDF(dhConcat, 1),
    headerKey:     x3dhKDF(dhConcat, 2),
    nextHeaderKey: x3dhKDF(dhConcat, 3),
  }
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

// ── Prekey generation ─────────────────────────────────────────────────────────

/**
 * Generates a signed prekey: a fresh X25519 key pair whose public half is
 * signed by the identity key.
 *
 * @param identity - The owner's identity key pair (Ed25519).
 * @param keyId    - Monotonic id for this prekey.
 * @example
 * const spk = await generateSignedPreKey(identity, 1)
 */
export async function generateSignedPreKey(
  identity: IdentityKeyPair,
  keyId: number
): Promise<SignedPreKey> {
  await _sodium.ready
  const pair = _sodium.crypto_box_keypair()
  const keyPair: KeyPair = { publicKey: pair.publicKey, privateKey: pair.privateKey }
  const signature = await sign(identity.privateKey, keyPair.publicKey)
  return { keyId, keyPair, signature }
}

/**
 * Generates a batch of one-time prekeys.
 *
 * @param startId - Id of the first prekey; subsequent ones increment from here.
 * @param count   - How many to generate (Signal uses ~100).
 * @example
 * const otps = await generateOneTimePreKeys(1, 100)
 */
export async function generateOneTimePreKeys(
  startId: number,
  count: number
): Promise<OneTimePreKey[]> {
  await _sodium.ready
  const keys: OneTimePreKey[] = []
  for (let i = 0; i < count; i++) {
    const pair = _sodium.crypto_box_keypair()
    keys.push({
      keyId: startId + i,
      keyPair: { publicKey: pair.publicKey, privateKey: pair.privateKey },
    })
  }
  return keys
}

/**
 * Assembles the public prekey bundle to publish to the key server.
 *
 * @param identity       - Owner's identity key pair.
 * @param signedPreKey   - The current signed prekey.
 * @param oneTimePreKey  - An optional one-time prekey to advertise.
 */
export function buildPreKeyBundle(
  identity: IdentityKeyPair,
  signedPreKey: SignedPreKey,
  oneTimePreKey?: OneTimePreKey
): PreKeyBundle {
  const bundle: PreKeyBundle = {
    identityKey: b64(identity.publicKey),
    signedPreKey: {
      keyId: signedPreKey.keyId,
      publicKey: b64(signedPreKey.keyPair.publicKey),
      signature: b64(signedPreKey.signature),
    },
  }
  if (oneTimePreKey) {
    bundle.oneTimePreKey = {
      keyId: oneTimePreKey.keyId,
      publicKey: b64(oneTimePreKey.keyPair.publicKey),
    }
  }
  return bundle
}

// ── X3DH handshake ─────────────────────────────────────────────────────────────

/**
 * Initiator side of X3DH (Alice contacting Bob).
 *
 * Verifies the recipient's signed prekey, performs the three (or four) DH
 * operations, and derives the shared secret. The returned `message` must be
 * sent to the recipient with the first ciphertext.
 *
 * @param myIdentity  - Initiator's identity key pair.
 * @param theirBundle - Recipient's published prekey bundle.
 * @throws {InvalidKeyError} If the signed prekey signature fails to verify —
 *   this is the MITM guard, so callers must not proceed past it.
 * @example
 * const init = await x3dhInitiate(myIdentity, bobBundle)
 * const ratchet = await DoubleRatchet.initSender(init.sharedSecret, init.signedPreKeyPublic)
 */
export async function x3dhInitiate(
  myIdentity: IdentityKeyPair,
  theirBundle: PreKeyBundle
): Promise<X3DHInitiation> {
  await _sodium.ready

  const theirIdentityEd = unb64(theirBundle.identityKey)
  const spkPublic       = unb64(theirBundle.signedPreKey.publicKey)
  const spkSignature    = unb64(theirBundle.signedPreKey.signature)

  // MITM guard: the signed prekey must carry a valid signature from the
  // claimed identity key. A malicious server cannot forge this without the
  // recipient's identity secret key.
  const sigOk = await verify(theirIdentityEd, spkPublic, spkSignature)
  if (!sigOk) {
    throw new InvalidKeyError(
      'Signed prekey signature is invalid — refusing to start a session (possible MITM).'
    )
  }

  // Ephemeral key for this handshake (provides forward secrecy).
  const ek = _sodium.crypto_box_keypair()

  // X25519 forms of the identity keys.
  const myIdentityX25519Priv = identityPrivateToX25519(myIdentity.privateKey)
  const theirIdentityX25519  = identityPublicToX25519(theirIdentityEd)

  // DH1 = DH(IK_A, SPK_B)   binds initiator identity to recipient prekey
  // DH2 = DH(EK_A, IK_B)    binds recipient identity to initiator ephemeral
  // DH3 = DH(EK_A, SPK_B)   ephemeral ↔ signed prekey
  // DH4 = DH(EK_A, OPK_B)   optional one-time prekey
  const dh1 = _sodium.crypto_scalarmult(myIdentityX25519Priv, spkPublic)
  const dh2 = _sodium.crypto_scalarmult(ek.privateKey, theirIdentityX25519)
  const dh3 = _sodium.crypto_scalarmult(ek.privateKey, spkPublic)

  const parts = [dh1, dh2, dh3]
  let oneTimePreKeyId: number | null = null
  if (theirBundle.oneTimePreKey) {
    const opkPublic = unb64(theirBundle.oneTimePreKey.publicKey)
    const dh4 = _sodium.crypto_scalarmult(ek.privateKey, opkPublic)
    parts.push(dh4)
    oneTimePreKeyId = theirBundle.oneTimePreKey.keyId
  }

  const sessionKeys = deriveSessionKeys(concatBytes(parts))

  // Wipe DH outputs and the X25519 identity private scalar.
  for (const p of parts) _sodium.memzero(p)
  _sodium.memzero(myIdentityX25519Priv)

  return {
    sessionKeys,
    signedPreKeyPublic: spkPublic,
    message: {
      identityKey: b64(myIdentity.publicKey),
      ephemeralKey: b64(ek.publicKey),
      signedPreKeyId: theirBundle.signedPreKey.keyId,
      oneTimePreKeyId,
    },
  }
}

/**
 * Responder side of X3DH (Bob receiving Alice's prekey message).
 *
 * Reconstructs the same shared secret using the responder's private prekeys and
 * the public keys carried in the prekey message.
 *
 * @param myIdentity      - Responder's identity key pair.
 * @param mySignedPreKey  - The responder's signed-prekey X25519 key pair whose
 *   id matches `message.signedPreKeyId`.
 * @param myOneTimePreKey - The responder's one-time prekey X25519 key pair whose
 *   id matches `message.oneTimePreKeyId`, or null when none was used. This key
 *   must be deleted by the caller after a successful handshake.
 * @param message         - The prekey message produced by `x3dhInitiate`.
 * @returns The 32-byte shared secret. Feed into `DoubleRatchet.initReceiver`.
 * @throws {DecryptionFailedError} If a one-time prekey id was referenced but no
 *   matching key was supplied.
 * @returns The session keys (root + header keys). Feed into
 *   `DoubleRatchet.initReceiver`.
 * @example
 * const keys = await x3dhRespond(myIdentity, mySpk, myOtp, msg)
 * const ratchet = await DoubleRatchet.initReceiver(keys, mySpkKeyPair)
 */
export async function x3dhRespond(
  myIdentity: IdentityKeyPair,
  mySignedPreKey: KeyPair,
  myOneTimePreKey: KeyPair | null,
  message: PreKeyMessage
): Promise<SessionKeys> {
  await _sodium.ready

  if (message.oneTimePreKeyId !== null && !myOneTimePreKey) {
    throw new DecryptionFailedError(
      `Prekey message referenced one-time prekey ${message.oneTimePreKeyId}, but no matching key was provided.`
    )
  }

  const theirIdentityEd = unb64(message.identityKey)
  const ephemeralPublic = unb64(message.ephemeralKey)

  const myIdentityX25519Priv = identityPrivateToX25519(myIdentity.privateKey)
  const theirIdentityX25519  = identityPublicToX25519(theirIdentityEd)

  // Mirror of the initiator's DH operations (scalarmult is symmetric):
  // DH1 = DH(SPK_B, IK_A)
  // DH2 = DH(IK_B, EK_A)
  // DH3 = DH(SPK_B, EK_A)
  // DH4 = DH(OPK_B, EK_A)
  const dh1 = _sodium.crypto_scalarmult(mySignedPreKey.privateKey, theirIdentityX25519)
  const dh2 = _sodium.crypto_scalarmult(myIdentityX25519Priv, ephemeralPublic)
  const dh3 = _sodium.crypto_scalarmult(mySignedPreKey.privateKey, ephemeralPublic)

  const parts = [dh1, dh2, dh3]
  if (message.oneTimePreKeyId !== null && myOneTimePreKey) {
    const dh4 = _sodium.crypto_scalarmult(myOneTimePreKey.privateKey, ephemeralPublic)
    parts.push(dh4)
  }

  const sessionKeys = deriveSessionKeys(concatBytes(parts))

  for (const p of parts) _sodium.memzero(p)
  _sodium.memzero(myIdentityX25519Priv)

  return sessionKeys
}
