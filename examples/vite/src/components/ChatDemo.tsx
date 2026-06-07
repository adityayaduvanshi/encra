import { useRef, useState, useEffect } from 'react'
import { useE2EChat, useE2EPresence } from '@encra/react'
import type { WireEvent } from '@encra/react'
import type { Config } from '../App'
import { StatusDot } from './StatusBadge'
import { emitLog } from '../lib/logger'

interface Props { config: Config; sessionId: string }

interface TaggedEvent extends WireEvent { from: string; id: number }

// ── Status dot for peer presence ───────────────────────────────────────────────

const STATUS_COLOR: Record<string, string> = {
  online:  'var(--accent)',
  offline: 'var(--text-3)',
  away:    'var(--amber)',
  busy:    'var(--red)',
}

// ── Chat panel ─────────────────────────────────────────────────────────────────

function ChatPanel({
  name, accent, userId, recipientId, config, onWire,
}: {
  name: string; accent: string; userId: string; recipientId: string
  config: Config; onWire: (e: TaggedEvent) => void
}) {
  const counter    = useRef(0)
  const sendNumRef = useRef(0)
  const recvNumRef = useRef(0)
  const typingTimerRef = useRef<ReturnType<typeof setTimeout>>()
  const didLogRef  = useRef(false)

  // ── Chat hook ──────────────────────────────────────────────────────────────

  const { messages, isReady, isConnecting, sendMessage, error } = useE2EChat({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
    onWireMessage: (e) => {
      onWire({ ...e, from: name, id: counter.current++ })
      if (e.direction === 'sent') {
        emitLog({
          category: 'TRANSPORT', actor: name,
          title: 'Ciphertext dispatched to relay',
          fields: [
            { label: 'ciphertext', value: e.ciphertext.slice(0, 44) + '…' },
            { label: 'nonce',      value: e.nonce.slice(0, 28) + '…'      },
            { label: 'route',      value: `${userId} → relay → ${recipientId}` },
            { label: 'plaintext',  value: '(never transmitted)' },
          ],
        })
      } else {
        recvNumRef.current++
        emitLog({
          category: 'RATCHET', actor: name,
          title: `Double Ratchet: decrypt message #${recvNumRef.current}`,
          fields: [
            { label: 'from',            value: recipientId                                    },
            { label: 'msg key',         value: 'derived from recv chain key → used → deleted' },
            { label: 'forward secrecy', value: '✓ decryption key erased after use'            },
          ],
        })
      }
    },
  })

  // ── Presence hook (runs alongside chat) ───────────────────────────────────

  const {
    presence, isReady: presenceReady, sendTyping,
  } = useE2EPresence({
    apiKey:    config.apiKey,
    userId,
    contacts:  [recipientId],
    serverUrl: config.serverUrl,
  })

  const peerInfo = presence[recipientId]
  // The hook broadcasts online automatically when ready and offline on unmount.

  // Log key registration + connection
  useEffect(() => {
    if (isReady && !didLogRef.current) {
      didLogRef.current = true
      emitLog({
        category: 'KEY', actor: name,
        title: 'X25519 key pair generated & registered',
        fields: [
          { label: 'userId',      value: userId                         },
          { label: 'algorithm',   value: 'X25519 (Curve25519 ECDH)'     },
          { label: 'public key',  value: 'uploaded → POST /v1/keys'     },
          { label: 'private key', value: 'stays on device — never sent' },
        ],
      })
      emitLog({
        category: 'SYSTEM', actor: name,
        title: 'WebSocket relay connected',
        fields: [
          { label: 'endpoint', value: '/v1/relay'          },
          { label: 'auth',     value: 'JWT Bearer (apiKey)' },
        ],
      })
    }
  }, [isReady, name, userId])

  useEffect(() => {
    if (error) emitLog({ category: 'ERROR', actor: name, title: error.message })
  }, [error, name])

  const [input, setInput] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // ── Input change: send typing indicator ─────────────────────────────────────

  function handleInputChange(val: string) {
    setInput(val)
    if (!presenceReady) return
    sendTyping(recipientId, val.length > 0)
    clearTimeout(typingTimerRef.current)
    if (val.length > 0) {
      typingTimerRef.current = setTimeout(() => sendTyping(recipientId, false), 2000)
    }
  }

  // ── Send ────────────────────────────────────────────────────────────────────

  async function send() {
    if (!input.trim() || !isReady) return
    const n = ++sendNumRef.current
    const isDH = n === 1
    emitLog({
      category: 'RATCHET', actor: name,
      title: `Double Ratchet: encrypt message #${n}`,
      fields: [
        { label: 'to',             value: recipientId                                             },
        { label: 'step',           value: isDH ? 'DH ratchet + symmetric ratchet' : 'symmetric ratchet step' },
        { label: 'msg key',        value: 'derived from send chain key → used → deleted'          },
        { label: 'forward secrecy',value: '✓ encryption key erased after use'                     },
        ...(isDH ? [{ label: 'DH ratchet', value: 'new ephemeral key pair → new root key' }] : []),
      ],
    })
    const text = input.trim()
    setInput('')
    // Clear typing indicator immediately on send
    if (presenceReady) {
      sendTyping(recipientId, false)
      clearTimeout(typingTimerRef.current)
    }
    try { await sendMessage(recipientId, text) }
    catch (e) { setInput(text); console.error(e) }
  }

  // Cleanup typing timer on unmount
  useEffect(() => () => clearTimeout(typingTimerRef.current), [])

  // ── Peer presence header info ───────────────────────────────────────────────

  const peerStatusText = peerInfo?.isTyping
    ? 'typing…'
    : peerInfo
    ? peerInfo.status
    : null

  const peerStatusColor = peerInfo?.isTyping
    ? 'var(--text-3)'
    : peerInfo
    ? STATUS_COLOR[peerInfo.status] ?? 'var(--text-3)'
    : 'var(--text-3)'

  return (
    <div className="panel flex flex-col" style={{ height: '100%' }}>
      {/* Header */}
      <div className="panel-header">
        <div className="flex items-center gap-2.5 min-w-0">
          {/* Avatar with presence ring */}
          <div style={{ position: 'relative', flexShrink: 0 }}>
            <div
              className="flex items-center justify-center mono font-medium"
              style={{
                width: 26, height: 26, borderRadius: 6,
                background: accent + '20',
                border: `1px solid ${accent}40`,
                fontSize: 11, color: accent,
              }}
            >
              {name[0]}
            </div>
          </div>

          <div className="min-w-0">
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', lineHeight: 1 }}>
              {name}
            </p>
            {/* Peer presence status */}
            {peerStatusText ? (
              <div className="flex items-center gap-1" style={{ marginTop: 2 }}>
                <span style={{
                  width: 5, height: 5, borderRadius: '50%',
                  background: peerStatusColor, display: 'inline-block', flexShrink: 0,
                }} />
                <span className="mono" style={{ fontSize: 10, color: peerStatusColor }}>
                  {peerInfo?.isTyping ? `${recipientId.split('-')[0]} is typing…` : peerStatusText}
                </span>
              </div>
            ) : (
              <p className="mono truncate" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>
                {userId}
              </p>
            )}
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={isConnecting} error={error} />
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto" style={{ padding: '12px 14px', minHeight: 0 }}>
        {messages.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <p className="mono text-center" style={{ fontSize: 11, color: 'var(--text-3)' }}>
              {isConnecting ? 'connecting…' : 'no messages yet'}
            </p>
          </div>
        )}
        <div className="space-y-1.5">
          {messages.map((m, i) => {
            const mine = m.from === userId
            return (
              <div key={i} className={`flex ${mine ? 'justify-end' : 'justify-start'}`}>
                <div
                  style={{
                    maxWidth: '82%',
                    padding: '7px 11px',
                    borderRadius: 10,
                    borderBottomRightRadius: mine ? 3 : 10,
                    borderBottomLeftRadius: mine ? 10 : 3,
                    fontSize: 13, lineHeight: 1.4,
                    background: mine ? accent : 'var(--bg-elevated)',
                    color: mine ? '#000' : 'var(--text-1)',
                    fontWeight: mine ? 500 : 400,
                  }}
                >
                  {m.text}
                </div>
              </div>
            )
          })}

          {/* Typing indicator bubble */}
          {peerInfo?.isTyping && (
            <div className="flex justify-start" style={{ marginTop: 4 }}>
              <div style={{
                padding: '7px 14px',
                borderRadius: 10, borderBottomLeftRadius: 3,
                background: 'var(--bg-elevated)',
                fontSize: 16, letterSpacing: 3,
                color: 'var(--text-3)',
              }}>
                •••
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          padding: '6px 14px', borderTop: '1px solid var(--border)',
          background: 'var(--red-dim)', fontSize: 11,
          color: 'var(--red)', fontFamily: 'JetBrains Mono',
        }}>
          {error.message}
        </div>
      )}

      {/* Input row */}
      <div
        className="flex items-center gap-2"
        style={{ padding: '10px 12px', borderTop: '1px solid var(--border)' }}
      >
        <input
          className="chat-input flex-1"
          value={input}
          onChange={(e) => handleInputChange(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && send()}
          placeholder={isReady ? `Message ${recipientId.split('-')[0]}…` : 'Connecting…'}
          disabled={!isReady}
        />
        <button
          className="btn btn-accent"
          style={{ padding: '6px 12px', fontSize: 12, flexShrink: 0 }}
          onClick={send}
          disabled={!isReady || !input.trim()}
        >
          Send
        </button>
      </div>
    </div>
  )
}

// ── Wire / terminal panel ──────────────────────────────────────────────────────

function WirePanel({ events, onClear }: { events: TaggedEvent[]; onClear: () => void }) {
  const bottomRef = useRef<HTMLDivElement>(null)
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [events])

  return (
    <div className="terminal">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: '#ff5f57' }} />
        <div className="terminal-dot" style={{ background: '#febc2e' }} />
        <div className="terminal-dot" style={{ background: '#28c840' }} />
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 8, flex: 1 }}>
          server.log
        </span>
        {events.length > 0 && (
          <button
            onClick={onClear}
            className="mono"
            style={{ fontSize: 9, color: 'var(--text-3)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-2)')}
            onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
          >
            clear
          </button>
        )}
      </div>

      <div className="terminal-body">
        {events.length === 0 ? (
          <div className="flex items-center justify-center" style={{ height: 120 }}>
            <p style={{ color: 'var(--text-3)', fontSize: 10 }}>
              send a message to see wire data
            </p>
          </div>
        ) : (
          events.map((e, idx) => (
            <div key={e.id} style={{ marginBottom: 10 }}>
              <div className="flex items-baseline gap-2">
                <span style={{ color: 'var(--text-3)', minWidth: 18, textAlign: 'right' }}>
                  {idx + 1}
                </span>
                <span style={{ color: e.direction === 'sent' ? 'var(--blue)' : 'var(--purple)' }}>
                  {e.direction === 'sent' ? '↑' : '↓'}{' '}
                </span>
                <span style={{ color: 'var(--text-2)' }}>{e.from}</span>
                <span style={{ color: 'var(--text-3)', fontSize: 9, marginLeft: 'auto' }}>
                  {new Date(e.timestamp).toLocaleTimeString([], { hour12: false })}
                </span>
              </div>
              <div style={{ paddingLeft: 26, marginTop: 2 }}>
                <div>
                  <span style={{ color: 'var(--text-3)' }}>ct  </span>
                  <span style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>
                    {e.ciphertext.slice(0, 32)}
                    <span style={{ color: 'var(--text-3)' }}>…</span>
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-3)' }}>n   </span>
                  <span style={{ color: 'var(--amber)' }}>
                    {e.nonce.slice(0, 22)}
                    <span style={{ color: 'var(--text-3)' }}>…</span>
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── ChatDemo ───────────────────────────────────────────────────────────────────

export default function ChatDemo({ config, sessionId }: Props) {
  const [events, setEvents] = useState<TaggedEvent[]>([])
  const aliceId = `alice-${sessionId}`
  const bobId   = `bob-${sessionId}`

  function addEvent(e: TaggedEvent) {
    setEvents((prev) => [...prev.slice(-49), e])
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, flex: 1, minHeight: 0 }}>
      {/* Info */}
      <div className="info-banner">
        <span style={{ color: 'var(--accent)', flexShrink: 0 }}>ℹ</span>
        <span>
          Two independent{' '}
          <span className="mono" style={{ color: 'var(--text-1)' }}>useE2EChat</span> +{' '}
          <span className="mono" style={{ color: 'var(--text-1)' }}>useE2EPresence</span> instances.
          Typing indicators and online status are encrypted — the relay sees only ciphertext.
        </span>
      </div>

      {/* Three columns */}
      <div style={{ display: 'flex', gap: 12, flex: 1, minHeight: 0 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <ChatPanel
            name="Alice" accent="var(--accent)"
            userId={aliceId} recipientId={bobId}
            config={config} onWire={addEvent}
          />
        </div>
        <div style={{ width: 220, flexShrink: 0 }}>
          <WirePanel events={events} onClear={() => setEvents([])} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <ChatPanel
            name="Bob" accent="var(--purple)"
            userId={bobId} recipientId={aliceId}
            config={config} onWire={addEvent}
          />
        </div>
      </div>
    </div>
  )
}
