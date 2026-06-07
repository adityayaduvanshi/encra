import { useState, useRef, useEffect, useCallback } from 'react'
import { useE2EPresence } from '@encra/react'
import type { PeerPresence, PresenceStatus } from '@encra/react'
import type { Config } from '../App'
import { StatusDot } from './StatusBadge'
import { emitLog } from '../lib/logger'

interface Props { config: Config; sessionId: string }

// ── Status helpers ─────────────────────────────────────────────────────────────

const STATUS_COLOR: Record<PresenceStatus, string> = {
  online:  'var(--accent)',
  offline: 'var(--text-3)',
  away:    'var(--amber)',
  busy:    'var(--red)',
}

function StatusCircle({ status, size = 7 }: { status: PresenceStatus; size?: number }) {
  return (
    <span style={{
      display: 'inline-block',
      width: size, height: size, borderRadius: '50%',
      background: STATUS_COLOR[status],
      flexShrink: 0,
    }} />
  )
}

// ── Wire event ─────────────────────────────────────────────────────────────────

interface WireEvent {
  id:        number
  direction: 'sent' | 'recv'
  actor:     string
  kind:      'status' | 'typing' | 'ghost'
  detail:    string
  time:      number
}

// ── Peer info card ─────────────────────────────────────────────────────────────

function PeerCard({ peerName, info }: { peerName: string; info: PeerPresence | undefined }) {
  if (!info) {
    return (
      <div style={{
        background: 'var(--bg-elevated)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '10px 12px',
      }}>
        <p className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
          Waiting for {peerName} to connect…
        </p>
      </div>
    )
  }
  return (
    <div style={{
      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '10px 12px',
    }}>
      <div className="flex items-center gap-2" style={{ marginBottom: 5 }}>
        <StatusCircle status={info.status} />
        <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-1)' }}>
          {info.status}
        </span>
        {info.isTyping && (
          <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 2 }}>
            ✎ typing…
          </span>
        )}
      </div>
      <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)' }}>
        last seen {info.lastSeenAt
          ? new Date(info.lastSeenAt).toLocaleTimeString([], { hour12: false })
          : '—'}
      </p>
    </div>
  )
}

// ── Presence panel ─────────────────────────────────────────────────────────────

function PresencePanel({
  name, accent, userId, peerId, config, onEvent,
}: {
  name: string; accent: string; userId: string; peerId: string
  config: Config; onEvent: (e: Omit<WireEvent, 'id'>) => void
}) {
  const [myStatus,    setMyStatus]    = useState<PresenceStatus>('online')
  const [typingInput, setTypingInput] = useState('')
  const typingTimerRef = useRef<ReturnType<typeof setTimeout>>()
  const prevInfoRef    = useRef<PeerPresence | undefined>()
  const didLogRef      = useRef(false)
  const peerName       = peerId.split('-')[0]!

  const {
    presence, isReady, ghostMode, setGhostMode, sendTyping, setStatus, error,
  } = useE2EPresence({
    apiKey:    config.apiKey,
    userId,
    contacts:  [peerId],
    serverUrl: config.serverUrl,
    onError:   (e) => emitLog({ category: 'ERROR', actor: name, title: e.message }),
  })

  const peerInfo = presence[peerId]

  // Log on ready
  useEffect(() => {
    if (isReady && !didLogRef.current) {
      didLogRef.current = true
      emitLog({
        category: 'KEY', actor: name,
        title: 'useE2EPresence ready — X3DH session on first send',
        fields: [
          { label: 'userId',    value: userId                               },
          { label: 'contacts',  value: peerId                               },
          { label: 'key model', value: 'OTP-free 3-DH X3DH (per session)'  },
          { label: 'domain',    value: 'encra:presence:v1'                  },
          { label: 'stored?',   value: 'no — presence is never queued'      },
        ],
      })
    }
  }, [isReady, name, userId, peerId])

  // Track incoming frames
  useEffect(() => {
    if (!peerInfo) return
    const prev = prevInfoRef.current
    if (!prev || prev.status !== peerInfo.status) {
      onEvent({ direction: 'recv', actor: peerName, kind: 'status', detail: peerInfo.status, time: Date.now() })
      emitLog({
        category: 'CRYPTO', actor: name,
        title: `Presence frame received and decrypted from ${peerName}`,
        fields: [
          { label: 'from',      value: peerId                                    },
          { label: 'cipher',    value: 'XSalsa20-Poly1305'                       },
          { label: 'key',       value: 'BLAKE2b(X3DH root, "encra:presence:v1")' },
          { label: 'decrypted', value: `status → ${peerInfo.status}`             },
        ],
      })
    }
    if (!prev || prev.isTyping !== peerInfo.isTyping) {
      onEvent({
        direction: 'recv', actor: peerName, kind: 'typing',
        detail: peerInfo.isTyping ? 'start' : 'stop', time: Date.now(),
      })
    }
    prevInfoRef.current = { ...peerInfo }
  }, [peerInfo, peerName, peerId, name, onEvent])

  // Status change
  const handleStatus = useCallback(async (s: PresenceStatus) => {
    if (!isReady || ghostMode) return
    setMyStatus(s)
    await setStatus(s)
    onEvent({ direction: 'sent', actor: name, kind: 'status', detail: s, time: Date.now() })
    emitLog({
      category: 'CRYPTO', actor: name,
      title: `Presence frame sent — status: ${s}`,
      fields: [
        { label: 'to',      value: peerId                                       },
        { label: 'cipher',  value: 'XSalsa20-Poly1305 + X3DH derived key'      },
        { label: 'stored?', value: 'no — ephemeral, relay routes and discards'  },
      ],
    })
  }, [isReady, ghostMode, peerId, name, setStatus, onEvent])

  // Ghost mode toggle
  const handleGhost = useCallback(async (enabled: boolean) => {
    await setGhostMode(enabled)
    onEvent({ direction: 'sent', actor: name, kind: 'ghost', detail: enabled ? 'on' : 'off', time: Date.now() })
    emitLog({
      category: 'SYSTEM', actor: name,
      title: `Ghost mode ${enabled ? 'enabled' : 'disabled'}`,
      fields: [{
        label: 'effect',
        value: enabled
          ? 'broadcasts offline to all contacts, suppresses future sends'
          : 'broadcasts online to all contacts',
      }],
    })
  }, [name, setGhostMode, onEvent])

  // Typing indicator
  const handleTypingInput = useCallback((val: string) => {
    setTypingInput(val)
    if (!isReady || ghostMode) return
    const typing = val.length > 0
    sendTyping(peerId, typing)
    clearTimeout(typingTimerRef.current)
    if (typing) {
      onEvent({ direction: 'sent', actor: name, kind: 'typing', detail: 'start', time: Date.now() })
      typingTimerRef.current = setTimeout(() => {
        sendTyping(peerId, false)
        onEvent({ direction: 'sent', actor: name, kind: 'typing', detail: 'stop', time: Date.now() })
      }, 2000)
    } else {
      onEvent({ direction: 'sent', actor: name, kind: 'typing', detail: 'stop', time: Date.now() })
    }
  }, [isReady, ghostMode, peerId, name, sendTyping, onEvent])

  // Cleanup typing timer on unmount
  useEffect(() => () => clearTimeout(typingTimerRef.current), [])

  return (
    <div className="panel flex flex-col" style={{ height: '100%' }}>
      {/* Header */}
      <div className="panel-header">
        <div className="flex items-center gap-2.5 min-w-0">
          <div style={{
            width: 26, height: 26, borderRadius: 6,
            background: accent + '20', border: `1px solid ${accent}40`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, color: accent, fontFamily: 'JetBrains Mono', fontWeight: 500,
            flexShrink: 0,
          }}>
            {name[0]}
          </div>
          <div className="min-w-0">
            <p style={{ fontSize: 13, fontWeight: 600, lineHeight: 1, color: 'var(--text-1)' }}>
              {name}
            </p>
            <p className="mono truncate" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>
              {ghostMode ? '👻 invisible' : `${myStatus}`}
            </p>
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={!isReady && !error} error={error} />
      </div>

      <div className="flex-1 overflow-y-auto" style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* Own status */}
        <section>
          <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Your status
          </p>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {(['online', 'away', 'busy', 'offline'] as PresenceStatus[]).map((s) => {
              const active = myStatus === s && !ghostMode
              return (
                <button
                  key={s}
                  onClick={() => handleStatus(s)}
                  disabled={!isReady || ghostMode}
                  style={{
                    padding: '4px 10px', borderRadius: 6, fontSize: 11,
                    cursor: !isReady || ghostMode ? 'not-allowed' : 'pointer',
                    fontFamily: 'JetBrains Mono',
                    display: 'flex', alignItems: 'center', gap: 5,
                    background: active ? STATUS_COLOR[s] + '22' : 'var(--bg-elevated)',
                    border: `1px solid ${active ? STATUS_COLOR[s] + '55' : 'var(--border)'}`,
                    color: active ? STATUS_COLOR[s] : 'var(--text-2)',
                    opacity: !isReady || ghostMode ? 0.4 : 1,
                    transition: 'all 0.1s',
                  }}
                >
                  <span style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: STATUS_COLOR[s], display: 'inline-block',
                  }} />
                  {s}
                </button>
              )
            })}
          </div>
        </section>

        {/* Ghost mode */}
        <section>
          <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Ghost mode
          </p>
          <button
            onClick={() => handleGhost(!ghostMode)}
            disabled={!isReady}
            style={{
              padding: '5px 12px', borderRadius: 6, fontSize: 11,
              fontFamily: 'JetBrains Mono', cursor: !isReady ? 'not-allowed' : 'pointer',
              background: ghostMode ? 'rgba(168,85,247,0.12)' : 'var(--bg-elevated)',
              border: `1px solid ${ghostMode ? 'rgba(168,85,247,0.4)' : 'var(--border)'}`,
              color: ghostMode ? 'var(--purple)' : 'var(--text-2)',
              opacity: !isReady ? 0.4 : 1,
            }}
          >
            {ghostMode ? '👻 Invisible — click to reappear' : '👻 Go invisible'}
          </button>
          {ghostMode && (
            <p className="mono" style={{ fontSize: 9, color: 'var(--purple)', marginTop: 5, opacity: 0.7 }}>
              All presence sends suppressed — others see you as offline
            </p>
          )}
        </section>

        {/* Typing demo input */}
        <section>
          <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Typing indicator
          </p>
          <input
            className="field"
            style={{ fontSize: 12 }}
            value={typingInput}
            onChange={(e) => handleTypingInput(e.target.value)}
            placeholder={
              !isReady      ? 'Connecting…'
              : ghostMode   ? 'Ghost mode on — sends suppressed'
              : `Type to send encrypted typing indicator to ${peerName}…`
            }
            disabled={!isReady || ghostMode}
          />
          <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 5 }}>
            Ephemeral · never stored · auto-clears after 2 s idle
          </p>
        </section>

        {/* Peer presence */}
        <section>
          <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            {peerName}'s presence (decrypted locally)
          </p>
          <PeerCard peerName={peerName} info={peerInfo} />
        </section>

      </div>
    </div>
  )
}

// ── Wire / presence log panel ──────────────────────────────────────────────────

const KIND_COLOR: Record<WireEvent['kind'], string> = {
  status: 'var(--accent)',
  typing: 'var(--amber)',
  ghost:  'var(--purple)',
}

function kindLabel(e: WireEvent): string {
  if (e.kind === 'status') return `status → ${e.detail}`
  if (e.kind === 'ghost')  return `ghost → ${e.detail}`
  return `typing → ${e.detail}`
}

function WirePanel({ events, onClear }: { events: WireEvent[]; onClear: () => void }) {
  const bottomRef = useRef<HTMLDivElement>(null)
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [events])

  return (
    <div className="terminal">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: '#ff5f57' }} />
        <div className="terminal-dot" style={{ background: '#febc2e' }} />
        <div className="terminal-dot" style={{ background: '#28c840' }} />
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 8, flex: 1 }}>
          presence.log
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
          <div className="flex items-center justify-center" style={{ height: 100 }}>
            <p style={{ color: 'var(--text-3)', fontSize: 10, textAlign: 'center', lineHeight: 1.6 }}>
              set a status or type to<br />see encrypted frames
            </p>
          </div>
        ) : (
          events.map((e, idx) => (
            <div key={e.id} style={{ marginBottom: 9 }}>
              <div className="flex items-baseline gap-2">
                <span style={{ color: 'var(--text-3)', minWidth: 16, textAlign: 'right', fontSize: 10 }}>
                  {idx + 1}
                </span>
                <span style={{ color: e.direction === 'sent' ? 'var(--blue)' : 'var(--purple)' }}>
                  {e.direction === 'sent' ? '↑' : '↓'}
                </span>
                <span style={{ color: 'var(--text-2)', fontSize: 11 }}>{e.actor}</span>
                <span style={{ color: KIND_COLOR[e.kind], flex: 1, fontSize: 11 }}>
                  {kindLabel(e)}
                </span>
                <span style={{ color: 'var(--text-3)', fontSize: 9 }}>
                  {new Date(e.time).toLocaleTimeString([], { hour12: false })}
                </span>
              </div>
              <div style={{ paddingLeft: 26, marginTop: 2 }}>
                <span className="mono" style={{ fontSize: 9, color: 'var(--text-3)' }}>
                  XSalsa20-Poly1305 · X3DH key · ephemeral
                </span>
              </div>
            </div>
          ))
        )}
        <div ref={bottomRef} />

        {events.length > 0 && (
          <div style={{ marginTop: 10, borderTop: '1px solid var(--border)', paddingTop: 8 }}>
            <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', lineHeight: 1.7 }}>
              Key = BLAKE2b(X3DH root, "encra:presence:v1")<br />
              Frames never stored — relay routes &amp; drops
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// ── PresenceDemo ───────────────────────────────────────────────────────────────

export default function PresenceDemo({ config, sessionId }: Props) {
  const [events, setEvents] = useState<WireEvent[]>([])
  const counter = useRef(0)

  const aliceId = `alice-${sessionId}`
  const bobId   = `bob-${sessionId}`

  const addEvent = useCallback((e: Omit<WireEvent, 'id'>) => {
    setEvents((prev) => [...prev.slice(-99), { ...e, id: counter.current++ }])
  }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, flex: 1, minHeight: 0 }}>
      {/* Info banner */}
      <div className="info-banner">
        <span style={{ color: 'var(--accent)', flexShrink: 0 }}>ℹ</span>
        <span>
          Presence frames are encrypted with{' '}
          <span className="mono" style={{ color: 'var(--text-1)' }}>XSalsa20-Poly1305</span>{' '}
          using a key derived from an OTP-free X3DH session —{' '}
          <span style={{ fontWeight: 500, color: 'var(--text-1)' }}>never stored on the server</span>.
          Ghost mode suppresses all sends and broadcasts offline.
        </span>
      </div>

      {/* Three columns */}
      <div style={{ display: 'flex', gap: 12, flex: 1, minHeight: 0 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <PresencePanel
            name="Alice" accent="var(--accent)"
            userId={aliceId} peerId={bobId}
            config={config} onEvent={addEvent}
          />
        </div>
        <div style={{ width: 210, flexShrink: 0 }}>
          <WirePanel events={events} onClear={() => setEvents([])} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <PresencePanel
            name="Bob" accent="var(--purple)"
            userId={bobId} peerId={aliceId}
            config={config} onEvent={addEvent}
          />
        </div>
      </div>
    </div>
  )
}
