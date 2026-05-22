import chalk from 'chalk'

export async function runKeygen(): Promise<void> {
  // Dynamically import to avoid loading libsodium unless keygen is actually invoked
  const { generateKeyPair, exportKey, sodiumReady } = await import('@encra/core')
  await sodiumReady()

  const kp = await generateKeyPair()
  const pubB64  = exportKey(kp.publicKey)
  const privB64 = exportKey(kp.privateKey)

  console.log(chalk.bold('\n  Generated X25519 Key Pair\n'))
  console.log(chalk.dim('  Public key  (share this):'))
  console.log(chalk.cyan('  ' + pubB64))
  console.log(chalk.dim('\n  Private key (keep secret):'))
  console.log(chalk.yellow('  ' + privB64))
  console.log(chalk.red('\n  ⚠  Never share your private key or commit it to git.\n'))
}
