export { generateKeyPair, exportKey, importKey, sodiumReady } from './crypto/keyPair.js'
export type { KeyPair } from './crypto/keyPair.js'

export { deriveSharedSecret } from './crypto/keyExchange.js'

export { encrypt, decrypt } from './crypto/encrypt.js'
export type { EncryptedMessage } from './crypto/encrypt.js'

export { generateFingerprint } from './crypto/fingerprint.js'

export { DoubleRatchet, MAX_SKIP_KEYS, RATCHET_VERSION } from './crypto/ratchet.js'
export type { MessageHeader, RatchetMessage, RatchetStateExport } from './crypto/ratchet.js'

export { InvalidKeyError, DecryptionFailedError, KeyNotFoundError } from './errors.js'
