#!/usr/bin/env node
import { Command } from 'commander'
import { runInit } from './commands/init.js'
import { runKeygen } from './commands/keygen.js'

const program = new Command()

program
  .name('encra')
  .description('Developer CLI for encra — Signal-level encryption for any app')
  .version('0.1.0')

program
  .command('init')
  .description('Interactive setup wizard — generates .env.example and starter code')
  .action(async () => {
    await runInit()
  })

program
  .command('keygen')
  .description('Generate a test X25519 key pair (useful for debugging)')
  .action(async () => {
    await runKeygen()
  })

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})
