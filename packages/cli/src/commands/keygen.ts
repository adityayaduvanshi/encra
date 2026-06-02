import chalk from 'chalk'
import { spinner, divider, s } from '../utils/print.js'

/**
 * Generate a fresh X25519 key pair and print both keys to stdout.
 * Pass --field to generate a symmetric field-encryption key instead.
 */
export async function runKeygen(opts: { field?: boolean } = {}): Promise<void> {
  const { generateKeyPair, exportKey, generateFingerprint, generateFieldKey, sodiumReady } = await import('@encra/core')

  console.log()
  const spin = spinner('Initializing libsodium…')
  await sodiumReady()
  spin.stop()

  // ── Field key mode ───────────────────────────────────────────────────────
  if (opts.field) {
    const key = await generateFieldKey()
    const b64 = exportKey(key)

    console.log(chalk.bold('  Field Encryption Key') + chalk.dim('  (XSalsa20-Poly1305 · 32 bytes)'))
    divider()
    console.log()

    console.log(`  ${chalk.dim('Key (base64url):')}`)
    console.log(`  ${chalk.cyan(b64)}`)
    console.log()

    console.log(`  ${s.warn}  ${chalk.yellow('Store in AWS Secrets Manager, Vault, or .env')}`)
    console.log(`  ${chalk.dim('     Never commit to source control.')}`)
    console.log()

    console.log(`  ${chalk.dim('Usage:')}`)
    console.log(`  ${chalk.dim('  import { encryptField, decryptField, importKey } from \'@encra/core\'')}`)
    console.log(`  ${chalk.dim('  const key       = importKey(process.env.FIELD_KEY)')}`)
    console.log(`  ${chalk.dim('  const encrypted = await encryptField(ssn, key)')}`)
    console.log()

    divider()
    console.log()
    return
  }

  // ── X25519 key pair mode (default) ───────────────────────────────────────
  const kp          = await generateKeyPair()
  const pub         = exportKey(kp.publicKey)
  const priv        = exportKey(kp.privateKey)
  const fingerprint = await generateFingerprint(kp.publicKey)

  console.log(chalk.bold('  X25519 Key Pair') + chalk.dim('  (libsodium · curve25519)'))
  divider()
  console.log()

  console.log(`  ${chalk.dim('Public key')}  ${chalk.dim('(safe to share / register on server):')}`)
  console.log(`  ${chalk.cyan(pub)}`)
  console.log()

  console.log(`  ${chalk.dim('Private key')}  ${chalk.red('(never share — never commit to git):')}`)
  console.log(`  ${chalk.yellow(priv)}`)
  console.log()

  console.log(`  ${chalk.dim('Fingerprint')}  ${chalk.dim('(human-readable safety number):')}`)
  console.log(`  ${chalk.dim(fingerprint)}`)
  console.log()

  divider()
  console.log()
}
