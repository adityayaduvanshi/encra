#!/usr/bin/env node
import { Command } from 'commander'
import { runInit } from './commands/init.js'
import { runKeygen } from './commands/keygen.js'
import { runPing } from './commands/ping.js'

const program = new Command()

program
  .name('encra')
  .description('CLI for Encra — Signal-level E2E encryption for any app')
  .version('0.2.0')

program
  .command('init')
  .description('Set up Encra in your project — generates .env.example and a starter component')
  .action(async () => {
    await runInit()
  })

program
  .command('keygen')
  .description('Generate a test X25519 key pair (useful for debugging and integration tests)')
  .action(async () => {
    await runKeygen()
  })

program
  .command('ping')
  .description('Check if the Encra server is reachable and your API key is valid')
  .option('-s, --server <url>',   'Server URL to check',          'https://api.encra.dev')
  .option('-k, --api-key <key>',  'API key to test authentication')
  .action(async (opts: { server: string; apiKey?: string }) => {
    await runPing(opts.server, opts.apiKey)
  })

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})
