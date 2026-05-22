export class InvalidKeyError extends Error {
  readonly name = 'InvalidKeyError'
  constructor(message: string) {
    super(message)
    Object.setPrototypeOf(this, InvalidKeyError.prototype)
  }
}

export class DecryptionFailedError extends Error {
  readonly name = 'DecryptionFailedError'
  constructor(message = 'Decryption failed. The key may be wrong or the ciphertext corrupted.') {
    super(message)
    Object.setPrototypeOf(this, DecryptionFailedError.prototype)
  }
}

export class KeyNotFoundError extends Error {
  readonly name = 'KeyNotFoundError'
  constructor(userId: string) {
    super(
      `Public key for user '${userId}' not found. Make sure ${userId} has registered before sending a message.`
    )
    Object.setPrototypeOf(this, KeyNotFoundError.prototype)
  }
}
