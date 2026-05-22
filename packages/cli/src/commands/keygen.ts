import chalk from 'chalk'
import { spinner, divider } from '../utils/print.js'

/**
 * Generate a fresh X25519 key pair and print both keys to stdout.
 * Useful for testing key exchange manually or verifying the crypto layer works.
 */
export async function runKeygen(): Promise<void> {
  const { generateKeyPair, exportKey, generateFingerprint, sodiumReady } = await import('@encra/core')

  console.log()
  const spin = spinner('Initializing libsodium…')
  await sodiumReady()
  spin.stop()

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
