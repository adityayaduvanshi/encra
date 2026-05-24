/**
 * @encra/client — Node.js Demo
 *
 * Tests EncraClient end-to-end: two clients exchange encrypted messages
 * using the same Double Ratchet crypto as the React hook.
 *
 * Usage:
 *   node demo-client.mjs                              # local server (auto-generates JWT)
 *   ENCRA_API_KEY=<key> node demo-client.mjs          # use a real key from encra.dev
 *   ENCRA_SERVER_URL=https://api.encra.dev node demo-client.mjs
 */

// ── Node.js polyfills ─────────────────────────────────────────────────────────

import { WebSocket } from 'ws'
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const jwt = require('./node_modules/jsonwebtoken/index.js')

// Polyfill WebSocket globally — EncraClient uses the global WebSocket constructor
globalThis.WebSocket = WebSocket

// ── Config ────────────────────────────────────────────────────────────────────

import { readFileSync } from 'fs'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

/** Read a single KEY=value line from a .env file (no external dep needed). */
function readEnvValue(filePath, key) {
  try {
    const lines = readFileSync(filePath, 'utf8').split('\n')
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith(`${key}=`)) return trimmed.slice(key.length + 1).trim()
    }
  } catch { /* file not found */ }
  return null
}

const SERVER = process.env.ENCRA_SERVER_URL ?? 'http://localhost:3000'

// JWT_SECRET: env var → server .env file → fallback default
const SECRET =
  process.env.JWT_SECRET ??
  readEnvValue(resolve(__dirname, 'packages/server/.env'), 'JWT_SECRET') ??
  'dev-secret-change-in-prod'

// If ENCRA_API_KEY is set, use it directly (e.g. a real key from encra.dev).
// Otherwise generate a short-lived JWT for the local dev server.
const API_KEY = process.env.ENCRA_API_KEY ?? jwt.sign({ developerId: 'demo' }, SECRET)

// ── Import the built @encra/client ────────────────────────────────────────────

const { EncraClient } = await import('./packages/client/dist/index.js')

// ── Helpers ───────────────────────────────────────────────────────────────────

const wait = (ms) => new Promise((r) => setTimeout(r, ms))

function waitForMessage(receivedArr, predicate, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(
      () => reject(new Error(`Timeout waiting for message after ${timeoutMs}ms`)),
      timeoutMs,
    )
    const check = setInterval(() => {
      const msg = receivedArr.find(predicate)
      if (msg) { clearInterval(check); clearTimeout(deadline); resolve(msg) }
    }, 50)
  })
}

// ── Demo ──────────────────────────────────────────────────────────────────────

console.log('\n📦  @encra/client — End-to-End Demo\n')
console.log(`   Server : ${SERVER}`)
console.log(`   API key: ${API_KEY.slice(0, 24)}...\n`)

// 1. Create two clients
const alice = new EncraClient({ apiKey: API_KEY, userId: 'demo-alice', serverUrl: SERVER })
const bob   = new EncraClient({ apiKey: API_KEY, userId: 'demo-bob',   serverUrl: SERVER })

const aliceReceived = []
const bobReceived   = []

// Only track *received* messages (from the other party) in these arrays
alice.on('message', (msg) => { if (msg.from !== 'demo-alice') aliceReceived.push(msg) })
bob.on('message',   (msg) => { if (msg.from !== 'demo-bob')   bobReceived.push(msg) })
alice.on('error',   (err) => console.error('  ⚠  Alice error:', err.message))
bob.on('error',     (err) => console.error('  ⚠  Bob error:',   err.message))

// 2. Connect both — connect() resolves when WebSocket is open and registered
console.log('🔌  Connecting...')
try {
  await Promise.all([alice.connect(), bob.connect()])
} catch (err) {
  console.error('\n❌  Connection failed:', err.message)
  console.error('    Is the server running? Try: npm start --workspace=packages/server\n')
  process.exit(1)
}
// Give the relay a moment to process both register frames
await wait(200)
console.log('✓  Alice connected and registered')
console.log('✓  Bob connected and registered\n')

// 3. Alice sends three messages — each encrypted with a different ratchet key
console.log('📨  Alice → Bob  (3 messages):')
const aliceMessages = [
  'Hello Bob! 🔐 This is message 1.',
  'Message 2 — different encryption key.',
  'Message 3 — forward secrecy in action! 🎉',
]
for (const text of aliceMessages) {
  await alice.sendMessage('demo-bob', text)
  console.log(`   → "${text}"`)
}

// 4. Wait for Bob to receive all three
console.log('\n⏳  Waiting for Bob to receive...')
for (let i = 0; i < aliceMessages.length; i++) {
  await waitForMessage(bobReceived, (m) => m.text === aliceMessages[i])
  console.log(`✓  Bob decrypted: "${bobReceived[i].text}"`)
}

// 5. Bob replies — triggers a DH ratchet step (direction flip)
console.log('\n📨  Bob → Alice  (reply):')
const replyText = 'Got all 3! Ratchet is working perfectly. 🔄'
await bob.sendMessage('demo-alice', replyText)
console.log(`   → "${replyText}"`)

console.log('\n⏳  Waiting for Alice to receive...')
await waitForMessage(aliceReceived, (m) => m.text === replyText)
console.log(`✓  Alice decrypted: "${aliceReceived[0].text}"`)

// 6. Verify message history on both clients
console.log('\n📋  Message history (alice.messages):')
alice.messages.forEach((m) =>
  console.log(`   [${m.from === 'demo-alice' ? 'me' : m.from}] ${m.text}`),
)

console.log('\n📋  Message history (bob.messages):')
bob.messages.forEach((m) =>
  console.log(`   [${m.from === 'demo-bob' ? 'me' : m.from}] ${m.text}`),
)

// 7. Sanity checks
const checks = [
  [bobReceived.length === 3,     'Bob received all 3 messages'],
  [aliceReceived.length === 1,   'Alice received Bob\'s reply'],
  [alice.messages.length === 4,  'Alice.messages has 4 entries (3 sent + 1 received)'],
  [bob.messages.length === 4,    'Bob.messages has 4 entries (3 received + 1 sent)'],
]

console.log('\n🔍  Checks:')
let allPassed = true
for (const [pass, label] of checks) {
  console.log(`   ${pass ? '✓' : '✗'}  ${label}`)
  if (!pass) allPassed = false
}

// 8. Clean up
alice.disconnect()
bob.disconnect()

if (!allPassed) {
  console.error('\n❌  Some checks failed.\n')
  process.exit(1)
}

console.log('\n✅  ALL CHECKS PASSED — @encra/client is working correctly.\n')
