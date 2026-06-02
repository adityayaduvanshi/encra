export { generateKeyPair, exportKey, importKey, sodiumReady } from './crypto/keyPair.js'
export type { KeyPair } from './crypto/keyPair.js'

export { deriveSharedSecret } from './crypto/keyExchange.js'

export { encrypt, decrypt } from './crypto/encrypt.js'
export type { EncryptedMessage } from './crypto/encrypt.js'

export { encryptField, decryptField, generateFieldKey } from './crypto/field.js'
export type { EncryptedField } from './crypto/field.js'

export { generateFingerprint } from './crypto/fingerprint.js'

export { DoubleRatchet, MAX_SKIP_KEYS, RATCHET_VERSION } from './crypto/ratchet.js'
export type { MessageHeader, RatchetMessage, RatchetStateExport } from './crypto/ratchet.js'

export {
  generateIdentityKeyPair,
  sign,
  verify,
  identityPublicToX25519,
  identityPrivateToX25519,
} from './crypto/identity.js'
export type { IdentityKeyPair } from './crypto/identity.js'

export {
  generateSignedPreKey,
  generateOneTimePreKeys,
  buildPreKeyBundle,
  x3dhInitiate,
  x3dhRespond,
} from './crypto/x3dh.js'
export type {
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
  PreKeyMessage,
  X3DHInitiation,
} from './crypto/x3dh.js'

export { InvalidKeyError, DecryptionFailedError, KeyNotFoundError } from './errors.js'
