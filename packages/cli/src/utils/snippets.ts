import type { Framework } from './detect.js'

const MANAGED_SERVER = 'https://api.encra.dev'

/**
 * Generate a .env.example file tailored to the framework's env-var conventions.
 */
export function envTemplate(framework: Framework, serverUrl: string, apiKey = ''): string {
  const prefix = framework === 'nextjs' ? 'NEXT_PUBLIC_' : framework === 'react' ? 'VITE_' : framework === 'react-native' ? 'EXPO_PUBLIC_' : ''
  const key = apiKey.trim() || 'e2e_live_your_key_here'
  const serverLine = serverUrl === MANAGED_SERVER
    ? `# ${prefix}ENCRA_SERVER_URL=${serverUrl}   # default — omit to use Encra managed server`
    : `${prefix}ENCRA_SERVER_URL=${serverUrl}`

  return [
    `# Encra — End-to-End Encryption`,
    `# Get your API key at https://encra.dev`,
    ``,
    `${prefix}ENCRA_API_KEY=${key}`,
    serverLine,
    ``,
  ].join('\n')
}

/* ------------------------------------------------------------------ */
/* Next.js snippet                                                      */
/* ------------------------------------------------------------------ */
export function nextjsSnippet(): string {
  return `'use client'

import { useState, useRef } from 'react'
import { useE2EChat } from '@encra/react'

interface Props {
  userId: string
  peerId: string
}

/**
 * Drop-in E2E encrypted chat component for Next.js.
 * Every message is encrypted on this device — the server never sees plaintext.
 */
export function EncraChat({ userId, peerId }: Props) {
  const [draft, setDraft] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const { messages, isReady, sendMessage, error } = useE2EChat({
    apiKey: process.env.NEXT_PUBLIC_ENCRA_API_KEY!,
    userId,
    // serverUrl: process.env.NEXT_PUBLIC_ENCRA_SERVER_URL, // optional: self-hosted
  })

  const handleSend = async () => {
    const text = draft.trim()
    if (!text || !isReady) return
    await sendMessage(peerId, text)
    setDraft('')
    inputRef.current?.focus()
  }

  if (error) return <p className="text-sm text-red-500">Error: {error.message}</p>

  return (
    <div className="flex flex-col gap-3 p-4">
      {/* Encryption status */}
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <span
          className={\`size-1.5 rounded-full \${
            isReady ? 'bg-green-500' : 'bg-yellow-400 animate-pulse'
          }\`}
        />
        {isReady ? '🔒 End-to-end encrypted' : 'Establishing encrypted session…'}
      </div>

      {/* Messages */}
      <div className="flex flex-col gap-2 min-h-[120px]">
        {messages.length === 0 && (
          <p className="text-xs text-muted-foreground">No messages yet.</p>
        )}
        {messages.map((m, i) => (
          <div key={i} className={\`flex \${m.from === userId ? 'justify-end' : 'justify-start'}\`}>
            <div
              className={\`max-w-[75%] rounded-2xl px-3 py-1.5 text-sm \${
                m.from === userId
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted text-foreground'
              }\`}
            >
              {m.text}
            </div>
          </div>
        ))}
      </div>

      {/* Input */}
      <div className="flex gap-2">
        <input
          ref={inputRef}
          className="flex-1 rounded-lg border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          placeholder="Message (end-to-end encrypted)…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          disabled={!isReady}
        />
        <button
          className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
          onClick={handleSend}
          disabled={!isReady || !draft.trim()}
        >
          Send
        </button>
      </div>
    </div>
  )
}
`
}

/* ------------------------------------------------------------------ */
/* React (Vite / CRA) snippet                                           */
/* ------------------------------------------------------------------ */
export function reactSnippet(): string {
  return `import { useState, useRef } from 'react'
import { useE2EChat } from '@encra/react'

interface Props {
  userId: string
  peerId: string
}

/**
 * Drop-in E2E encrypted chat component for React (Vite / CRA).
 * Every message is encrypted on this device — the server never sees plaintext.
 */
export function EncraChat({ userId, peerId }: Props) {
  const [draft, setDraft] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const { messages, isReady, sendMessage, error } = useE2EChat({
    // Vite exposes env vars via import.meta.env
    apiKey: (import.meta as unknown as { env: Record<string, string> }).env['VITE_ENCRA_API_KEY'] ?? '',
    userId,
    // serverUrl: import.meta.env.VITE_ENCRA_SERVER_URL, // optional: self-hosted
  })

  const handleSend = async () => {
    const text = draft.trim()
    if (!text || !isReady) return
    await sendMessage(peerId, text)
    setDraft('')
    inputRef.current?.focus()
  }

  if (error) return <p style={{ color: 'red', fontSize: 14 }}>Error: {error.message}</p>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 16 }}>
      <small style={{ color: isReady ? '#16a34a' : '#ca8a04' }}>
        {isReady ? '🔒 End-to-end encrypted' : 'Establishing encrypted session…'}
      </small>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minHeight: 120 }}>
        {messages.length === 0 && <small style={{ color: '#6b7280' }}>No messages yet.</small>}
        {messages.map((m, i) => (
          <div key={i} style={{ textAlign: m.from === userId ? 'right' : 'left' }}>
            <span
              style={{
                display: 'inline-block',
                background: m.from === userId ? '#000' : '#f3f4f6',
                color: m.from === userId ? '#fff' : '#111',
                borderRadius: 12,
                padding: '6px 12px',
                fontSize: 14,
              }}
            >
              {m.text}
            </span>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <input
          ref={inputRef}
          style={{ flex: 1, borderRadius: 8, border: '1px solid #e5e7eb', padding: '8px 12px', fontSize: 14 }}
          placeholder="Message (end-to-end encrypted)…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          disabled={!isReady}
        />
        <button
          style={{
            borderRadius: 8, background: '#000', color: '#fff',
            padding: '8px 16px', fontSize: 14, cursor: 'pointer',
            opacity: !isReady || !draft.trim() ? 0.5 : 1,
          }}
          onClick={handleSend}
          disabled={!isReady || !draft.trim()}
        >
          Send
        </button>
      </div>
    </div>
  )
}
`
}

/* ------------------------------------------------------------------ */
/* React Native / Expo snippet                                          */
/* ------------------------------------------------------------------ */
export function reactNativeSnippet(): string {
  return `import { useState } from 'react'
import {
  View, Text, TextInput, TouchableOpacity,
  FlatList, StyleSheet,
} from 'react-native'
import { useE2EChat } from '@encra/react'

interface Props {
  userId: string
  peerId: string
}

/**
 * Drop-in E2E encrypted chat screen for React Native / Expo.
 * Every message is encrypted on this device — the server never sees plaintext.
 */
export function EncraChat({ userId, peerId }: Props) {
  const [draft, setDraft] = useState('')

  const { messages, isReady, sendMessage, error } = useE2EChat({
    apiKey: process.env.EXPO_PUBLIC_ENCRA_API_KEY ?? '',
    userId,
    // serverUrl: process.env.EXPO_PUBLIC_ENCRA_SERVER_URL, // optional: self-hosted
  })

  const handleSend = async () => {
    const text = draft.trim()
    if (!text || !isReady) return
    await sendMessage(peerId, text)
    setDraft('')
  }

  if (error) return <Text style={{ color: 'red' }}>Error: {error.message}</Text>

  return (
    <View style={styles.container}>
      <Text style={[styles.status, { color: isReady ? '#16a34a' : '#ca8a04' }]}>
        {isReady ? '🔒 End-to-end encrypted' : 'Connecting…'}
      </Text>

      <FlatList
        data={messages}
        keyExtractor={(_, i) => String(i)}
        style={styles.list}
        renderItem={({ item: m }) => (
          <View style={[styles.bubble, m.from === userId ? styles.mine : styles.theirs]}>
            <Text style={m.from === userId ? styles.mineText : styles.theirsText}>
              {m.text}
            </Text>
          </View>
        )}
      />

      <View style={styles.row}>
        <TextInput
          style={styles.input}
          placeholder="Message (end-to-end encrypted)…"
          value={draft}
          onChangeText={setDraft}
          onSubmitEditing={handleSend}
          editable={isReady}
        />
        <TouchableOpacity
          style={[styles.btn, !isReady && styles.btnDisabled]}
          onPress={handleSend}
          disabled={!isReady}
        >
          <Text style={styles.btnText}>Send</Text>
        </TouchableOpacity>
      </View>
    </View>
  )
}

const styles = StyleSheet.create({
  container:   { flex: 1, padding: 16 },
  status:      { fontSize: 12, marginBottom: 8 },
  list:        { flex: 1 },
  bubble:      { marginVertical: 3, borderRadius: 12, paddingHorizontal: 12, paddingVertical: 8, maxWidth: '75%' },
  mine:        { alignSelf: 'flex-end',   backgroundColor: '#000' },
  theirs:      { alignSelf: 'flex-start', backgroundColor: '#f3f4f6' },
  mineText:    { color: '#fff', fontSize: 14 },
  theirsText:  { color: '#111', fontSize: 14 },
  row:         { flexDirection: 'row', gap: 8, marginTop: 8 },
  input:       { flex: 1, borderWidth: 1, borderColor: '#e5e7eb', borderRadius: 8, padding: 10, fontSize: 14 },
  btn:         { backgroundColor: '#000', borderRadius: 8, justifyContent: 'center', paddingHorizontal: 16 },
  btnDisabled: { opacity: 0.4 },
  btnText:     { color: '#fff', fontSize: 14 },
})
`
}

/* ------------------------------------------------------------------ */
/* Node.js snippet                                                      */
/* ------------------------------------------------------------------ */
export function nodeSnippet(serverUrl: string): string {
  return `/**
 * Encra — Node.js starter
 * Full Alice→Bob E2E encrypted message flow using Double Ratchet.
 *
 * Run: npx ts-node encra-example.ts
 */
import {
  generateKeyPair,
  exportKey,
  importKey,
  deriveSharedSecret,
  sodiumReady,
  DoubleRatchet,
} from '@encra/core'

const SERVER  = process.env.ENCRA_SERVER_URL ?? '${serverUrl}'
const API_KEY = process.env.ENCRA_API_KEY    ?? ''

if (!API_KEY) {
  console.error('Set ENCRA_API_KEY in your .env file.')
  process.exit(1)
}

const headers = {
  'Content-Type': 'application/json',
  Authorization: \`Bearer \${API_KEY}\`,
}

async function register(userId: string, publicKey: string): Promise<void> {
  const res = await fetch(\`\${SERVER}/v1/keys\`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ userId, publicKey }),
  })
  if (!res.ok) throw new Error(\`Registration failed: \${res.status}\`)
}

async function getPublicKey(userId: string): Promise<string> {
  const res = await fetch(\`\${SERVER}/v1/keys/\${userId}\`, { headers })
  if (!res.ok) throw new Error(\`User '\${userId}' not found. Did they register?\`)
  const { publicKey } = (await res.json()) as { publicKey: string }
  return publicKey
}

async function main(): Promise<void> {
  await sodiumReady()
  console.log('✓  libsodium ready')

  // ── Alice registers ───────────────────────────────────────────────
  const aliceKP = await generateKeyPair()
  await register('alice', exportKey(aliceKP.publicKey))
  console.log('✓  Alice registered')

  // ── Bob registers ─────────────────────────────────────────────────
  const bobKP = await generateKeyPair()
  await register('bob', exportKey(bobKP.publicKey))
  console.log('✓  Bob registered')

  // ── Alice fetches Bob's key and encrypts ──────────────────────────
  const bobPub       = importKey(await getPublicKey('bob'))
  const aliceShared  = await deriveSharedSecret(aliceKP.privateKey, bobPub)
  const aliceRatchet = await DoubleRatchet.initSender(aliceShared, bobPub)

  const encrypted = aliceRatchet.encrypt('Hello Bob! 🔒')
  console.log('✓  Alice encrypted message')

  // ── Bob fetches Alice's key and decrypts ──────────────────────────
  const alicePub   = importKey(await getPublicKey('alice'))
  const bobShared  = await deriveSharedSecret(bobKP.privateKey, alicePub)
  const bobRatchet = await DoubleRatchet.initReceiver(bobShared, bobKP)

  const plaintext = bobRatchet.decrypt(encrypted)
  console.log('✓  Bob decrypted:', plaintext)

  console.log()
  console.log('🎉  E2E encryption working. The server never saw the plaintext.')
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})
`
}
