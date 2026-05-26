# Encra — Cryptography Reference

All cryptographic operations use **libsodium** (`libsodium-wrappers`).
No custom primitives. No WebCrypto. No node:crypto.

---

## Primitives Used

| Purpose | Primitive | libsodium function |
|---|---|---|
| Key pair generation | X25519 (Curve25519) | `crypto_box_keypair` |
| Key exchange | X25519 ECDH | `crypto_scalarmult` |
| Symmetric encryption | XSalsa20-Poly1305 | `crypto_secretbox_easy` |
| KDF / ratchet PRF | Keyed BLAKE2b-256 | `crypto_generichash` |
| Fingerprint / safety numbers | BLAKE2b-256 | `crypto_generichash` |
| Random bytes | CSPRNG | `randombytes_buf` |

---

## Key Pair (`@encra/core`)

```typescript
const kp = await generateKeyPair()
// kp.publicKey  — 32-byte Uint8Array (X25519 public key)
// kp.privateKey — 32-byte Uint8Array (X25519 scalar)

const b64  = exportKey(kp.publicKey)   // URL-safe base64 string
const back = importKey(b64)            // Uint8Array
```

Keys are stored in IndexedDB as base64 strings, never in localStorage.

---

## ECDH Key Exchange

```typescript
const shared = await deriveSharedSecret(alice.privateKey, bob.publicKey)
// → 32-byte shared secret (same result as bob.privateKey × alice.publicKey)
// Uses libsodium crypto_scalarmult (Montgomery ladder, constant time)
```

The shared secret is used as the root key to initialise the Double Ratchet, not
directly for encryption (avoids static-key vulnerabilities).

---

## Symmetric Encryption (messages and fields)

```typescript
const { ciphertext, nonce } = await encrypt(plaintext, key)
// ciphertext — XSalsa20-Poly1305, includes 16-byte Poly1305 MAC
// nonce      — 24 random bytes (libsodium randombytes_buf)
// key        — 32-byte symmetric key

const text = await decrypt({ ciphertext, nonce }, key)
```

Every call generates a **fresh random nonce**. The same key may be reused across
many calls safely (XSalsa20 nonce space is 2¹⁹² — negligible collision probability).

---

## Double Ratchet

Encra's Double Ratchet is a faithful implementation of the
[Signal Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/).

### State

```
State {
  DHs   — current sender DH key pair (ephemeral, rotated on DH ratchet step)
  DHr   — last received DH public key
  RK    — 32-byte root key
  CKs   — 32-byte sending chain key  (null until first send)
  CKr   — 32-byte receiving chain key (null until first receive)
  Ns    — message counter for current sending chain
  Nr    — message counter for current receiving chain
  PN    — number of messages in previous sending chain
  MKSKIPPED — Map<string, Uint8Array> of skipped message keys (up to 1000)
}
```

### KDF Chain (symmetric ratchet step)

```
KDF(chainKey, constant) → [newChainKey, messageKey]

Uses keyed BLAKE2b-256:
  newChainKey  = BLAKE2b(key=chainKey, data=0x01, len=32)
  messageKey   = BLAKE2b(key=chainKey, data=0x02, len=32)
```

`crypto_generichash` (BLAKE2b) is used instead of HMAC-SHA256 because libsodium's
standard build does not include `crypto_auth_hmacsha256` (only in `-sumo`). BLAKE2b
is equally sound as a PRF for KDF purposes.

### DH Ratchet Step

Triggered when a message is received with a new DH public key in the header:

```
1. Generate new ephemeral key pair DHs'
2. RK', CKr = KDF_RK(RK, DH(DHs, DHr_new))
3. RK'', CKs = KDF_RK(RK', DH(DHs', DHr_new))
4. DHs = DHs', DHr = DHr_new
5. Reset Ns, Nr
```

This gives **break-in recovery**: even if an attacker captures the current state,
future messages become secure again after the next DH ratchet step.

### Message Format (wire)

```typescript
interface RatchetMessage {
  header: {
    dh: string   // sender's current DHs public key (base64)
    pn: number   // messages in previous sending chain
    n:  number   // message number in current chain
  }
  ciphertext: Uint8Array  // XSalsa20-Poly1305 encrypted plaintext
  nonce:      Uint8Array  // random 24 bytes
}
```

The `header` is transmitted in plaintext. In the current implementation the header
is not encrypted; a future hardening step would encrypt it with a separate header key.

### Out-of-Order Delivery

If a message arrives out of order (e.g. `n=5` arrives before `n=3`), the ratchet
computes and stores message keys for the skipped messages in `MKSKIPPED`. When the
skipped messages arrive, their keys are retrieved from the map rather than recomputed.

`MAX_SKIP_KEYS = 1000` — the maximum number of skipped keys stored to prevent
denial-of-service via crafted headers.

### State Persistence

```typescript
const exported = ratchet.export()  // RatchetStateExport — all fields as base64 strings
const restored = await DoubleRatchet.fromExport(exported)
```

State is saved to IndexedDB after every `encrypt()` and `decrypt()` call, so
conversations survive page reloads without losing forward secrecy.

---

## Field Encryption (`@encra/core`)

A standalone utility for encrypting individual database fields — no server, no
ratchet, no React dependency.

```typescript
const key = await generateFieldKey()            // 32-byte CSPRNG key
const enc = await encryptField('123-45-6789', key)
// enc.ciphertext — URL-safe base64, XSalsa20-Poly1305 + fresh nonce
// enc.nonce      — URL-safe base64, 24 random bytes

const ssn = await decryptField(enc, key)        // '123-45-6789'
```

Use case: HIPAA fields in a PostgreSQL database. Store `key` in an environment
variable or secrets manager; store `{ ciphertext, nonce }` alongside the record.

---

## Safety Numbers / Fingerprint

```typescript
const fingerprint = await generateFingerprint(alice.publicKey, bob.publicKey)
// → 60-character numeric string (like Signal's safety numbers)
// = BLAKE2b-256(concat(sorted(alicePub, bobPub))) as decimal groups
```

Display to both users to allow out-of-band verification that no MITM is occurring.
If the strings match on both sides, the key exchange is authentic.

---

## Security Considerations

### Why not WebCrypto?
libsodium provides a stable, well-audited, opinionated API that prevents misuse.
WebCrypto's `SubtleCrypto` is more powerful but also more footgun-prone (manual IV
management, algorithm parameters, etc.). All Encra crypto goes through libsodium.

### Why BLAKE2b instead of HKDF?
libsodium's standard build (`libsodium-wrappers`) does not ship `crypto_kdf` or
`crypto_auth_hmacsha256`. BLAKE2b (`crypto_generichash`) in keyed mode is a secure
PRF and is available in the standard build. Semantically equivalent for our purposes.

### Nonce reuse
XSalsa20 with a 192-bit nonce: collision probability for `n` random nonces is
approximately `n² / 2¹⁹²` — effectively zero for any realistic message volume.
Each `encrypt()` / `encryptField()` call generates a fresh nonce via `randombytes_buf`.

### Key storage
Private keys are stored in IndexedDB (not localStorage). IndexedDB is origin-isolated
and not accessible to injected scripts from other origins. The current implementation
stores the private key as base64 without encryption at rest; a future improvement
would wrap the private key with a device-bound key from the WebAuthn/Credential
Management API.
