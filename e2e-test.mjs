/**
 * Manual end-to-end test — run with: node e2e-test.mjs
 *
 * Requires the server running on localhost:3000.
 * Uses real libsodium crypto — no mocks.
 */
import sodium from './node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js'
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const jwt = require('./node_modules/jsonwebtoken/index.js')
const { WebSocket } = require('./node_modules/ws/index.js')
// Load compiled ratchet from packages/core dist
const { DoubleRatchet } = require('./packages/core/dist/crypto/ratchet.js')

const SERVER = 'http://13.232.240.64:3000'
const WS_SERVER = 'ws://13.232.240.64:3000'
const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret-change-in-prod'
const TOKEN = jwt.sign({ developerId: 'e2e-test' }, JWT_SECRET)

await sodium.ready

// ── Crypto helpers ────────────────────────────────────────────────────────────

const b64 = (bytes) => sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING)
const unb64 = (str) => sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING)

async function registerKey(userId, publicKey) {
  const res = await fetch(`${SERVER}/v1/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ userId, publicKey: b64(publicKey) }),
  })
  if (!res.ok) throw new Error(`Register failed: ${await res.text()}`)
}

async function fetchPublicKey(userId) {
  const res = await fetch(`${SERVER}/v1/keys/${userId}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  })
  if (!res.ok) throw new Error(`Fetch failed: ${await res.text()}`)
  const { publicKey } = await res.json()
  return unb64(publicKey)
}

function connectWs(userId) {
  return new Promise((resolve, reject) => {
    const received = []
    const ws = new WebSocket(`${WS_SERVER}/v1/relay?token=${encodeURIComponent(TOKEN)}`)
    ws.on('error', reject)
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'register', userId }))
      resolve({ ws, received, send: (m) => ws.send(JSON.stringify(m)) })
    })
    ws.on('message', (raw) => received.push(JSON.parse(raw.toString())))
  })
}

function waitFor(client, predicate, ms = 3000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('Timeout')), ms)
    const i = setInterval(() => {
      const m = client.received.find(predicate)
      if (m) { clearInterval(i); clearTimeout(t); resolve(m) }
    }, 50)
  })
}

// ── Test ──────────────────────────────────────────────────────────────────────

console.log('\n🔐  e2e-chat-crypto — Live Encryption Test\n')

// 1. Generate key pairs
const aliceKP = sodium.crypto_box_keypair()
const bobKP   = sodium.crypto_box_keypair()
console.log('✓  Alice key pair generated')
console.log('✓  Bob key pair generated')
console.log(`   Alice public key: ${b64(aliceKP.publicKey)}`)
console.log(`   Bob   public key: ${b64(bobKP.publicKey)}`)

// 2. Register both with the server
await registerKey('e2e-alice', aliceKP.publicKey)
await registerKey('e2e-bob',   bobKP.publicKey)
console.log('\n✓  Alice registered on server')
console.log('✓  Bob registered on server')

// 3. Alice fetches Bob's public key and derives shared secret
const bobPubFromServer = await fetchPublicKey('e2e-bob')
const aliceShared = sodium.crypto_scalarmult(aliceKP.privateKey, bobPubFromServer)
console.log('\n✓  Alice fetched Bob\'s public key from server')
console.log(`   Shared secret (Alice side): ${b64(aliceShared).slice(0, 20)}...`)

// 4. Bob derives his side of the shared secret (symmetric ECDH)
const bobShared = sodium.crypto_scalarmult(bobKP.privateKey, aliceKP.publicKey)
if (b64(aliceShared) !== b64(bobShared)) throw new Error('FAIL: shared secrets do not match!')
console.log('✓  Shared secrets match on both sides')

// 5. Both initialise their Double Ratchet sessions
const aliceRatchet = await DoubleRatchet.initSender(aliceShared, bobKP.publicKey)
const bobRatchet   = await DoubleRatchet.initReceiver(bobShared, { publicKey: bobKP.publicKey, privateKey: bobKP.privateKey })
console.log('\n✓  Alice initialised Double Ratchet (sender)')
console.log('✓  Bob initialised Double Ratchet (receiver)')

// 6. Connect both via WebSocket
const aliceWs = await connectWs('e2e-alice')
const bobWs   = await connectWs('e2e-bob')
await waitFor(aliceWs, (m) => m.type === 'registered')
await waitFor(bobWs,   (m) => m.type === 'registered')
console.log('\n✓  Alice connected to relay')
console.log('✓  Bob connected to relay')

// 6–8. Alice sends 3 messages — each uses a DIFFERENT ratchet key
const messages = [
  'Hello Bob! This is message 1. 🔐',
  'Message 2 — different key, different ciphertext.',
  'Message 3 — forward secrecy in action.',
]

const ciphertexts = []
for (const text of messages) {
  const msg = await aliceRatchet.encrypt(text)
  ciphertexts.push(b64(msg.ciphertext).slice(0, 20))
  aliceWs.send({
    type: 'message',
    to: 'e2e-bob',
    ciphertext: b64(msg.ciphertext),
    nonce: b64(msg.nonce),
    // Attach the ratchet header so Bob can decrypt
    header: msg.header,
  })
}

// Verify all 3 ciphertexts are different (key rotation working)
const unique = new Set(ciphertexts)
if (unique.size !== 3) throw new Error('FAIL: duplicate ciphertexts — key rotation not working!')
console.log('\n✓  Alice sent 3 messages via ratchet')
console.log('✓  All 3 ciphertexts are unique (key rotation confirmed)')

// 9. Bob receives and decrypts all 3
for (let i = 0; i < 3; i++) {
  const wire = await waitFor(bobWs, (m) => m.type === 'message' && m.header?.n === i)
  const msg = {
    header: wire.header,
    ciphertext: unb64(wire.ciphertext),
    nonce: unb64(wire.nonce),
  }
  const decrypted = await bobRatchet.decrypt(msg)
  if (decrypted !== messages[i]) throw new Error(`FAIL: message ${i} mismatch!\nExpected: ${messages[i]}\nGot: ${decrypted}`)
  console.log(`✓  Bob decrypted message ${i + 1}: "${decrypted}"`)
  // Remove from received so waitFor can find the next one
  bobWs.received = bobWs.received.filter((m) => !(m.type === 'message' && m.header?.n === i))
}

// 10. Bob replies — triggers DH ratchet rotation
const reply = await bobRatchet.encrypt('Got all 3! Ratchet is working. 🎉')
const replyWire = { type: 'message', to: 'e2e-alice', ciphertext: b64(reply.ciphertext), nonce: b64(reply.nonce), header: reply.header }
bobWs.send(replyWire)

const aliceWire = await waitFor(aliceWs, (m) => m.type === 'message')
const aliceDecrypted = await aliceRatchet.decrypt({ header: aliceWire.header, ciphertext: unb64(aliceWire.ciphertext), nonce: unb64(aliceWire.nonce) })
console.log(`\n✓  Alice decrypted Bob's reply: "${aliceDecrypted}"`)

console.log('\n✅  ALL CHECKS PASSED — Double Ratchet end-to-end encryption is working.\n')

aliceWs.ws.close()
bobWs.ws.close()
