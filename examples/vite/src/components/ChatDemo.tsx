import { useRef, useState, useEffect } from 'react'
import { useE2EChat } from '@encra/react'
import type { WireEvent } from '@encra/react'
import type { Config } from '../App'
import { StatusBadge } from './StatusBadge'

interface Props {
  config: Config
  sessionId: string
}

interface TaggedWireEvent extends WireEvent {
  from: string
  id: number
}

// ── Individual chat panel ──────────────────────────────────────────────────────

interface PanelProps {
  name: string
  emoji: string
  userId: string
  recipientId: string
  config: Config
  onWire: (e: TaggedWireEvent) => void
}

function ChatPanel({ name, emoji, userId, recipientId, config, onWire }: PanelProps) {
  const counterRef = useRef(0)
  const { messages, isReady, isConnecting, sendMessage, error } = useE2EChat({
    apiKey:    config.apiKey,
    userId,
    serverUrl: config.serverUrl,
    onWireMessage: (e) =>
      onWire({ ...e, from: name, id: counterRef.current++ }),
  })

  const [input, setInput] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function send() {
    if (!input.trim() || !isReady) return
    try {
      await sendMessage(recipientId, input.trim())
      setInput('')
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xl shrink-0">{emoji}</span>
          <div className="min-w-0">
            <p className="font-semibold text-slate-100 leading-none">{name}</p>
            <p className="text-xs text-slate-500 font-mono truncate mt-0.5">{userId}</p>
          </div>
        </div>
        <StatusBadge isReady={isReady} isConnecting={isConnecting} error={error} />
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2 min-h-0">
        {messages.length === 0 && (
          <p className="text-center text-slate-600 text-sm pt-8">
            {isConnecting ? 'Connecting…' : 'No messages yet'}
          </p>
        )}
        {messages.map((m, i) => {
          const isMine = m.from === userId
          return (
            <div key={i} className={`flex ${isMine ? 'justify-end' : 'justify-start'}`}>
              <div
                className={`max-w-[85%] px-3 py-2 rounded-2xl text-sm leading-relaxed ${
                  isMine
                    ? 'bg-emerald-700 text-white rounded-br-sm'
                    : 'bg-slate-700 text-slate-100 rounded-bl-sm'
                }`}
              >
                {m.text}
              </div>
            </div>
          )
        })}
        <div ref={bottomRef} />
      </div>

      {/* Error toast */}
      {error && (
        <div className="px-4 py-2 bg-red-950 border-t border-red-900 text-xs text-red-400 shrink-0">
          {error.message}
        </div>
      )}

      {/* Input */}
      <div className="p-3 border-t border-slate-800 flex gap-2 shrink-0">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && send()}
          placeholder={isReady ? `Message as ${name}…` : 'Waiting for connection…'}
          disabled={!isReady}
          className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 disabled:opacity-40 focus:outline-none focus:border-emerald-500 transition-colors"
        />
        <button
          onClick={send}
          disabled={!isReady || !input.trim()}
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded-lg text-sm font-medium transition-colors shrink-0"
        >
          Send
        </button>
      </div>
    </div>
  )
}

// ── Wire events panel ─────────────────────────────────────────────────────────

function WirePanel({ events }: { events: TaggedWireEvent[] }) {
  const bottomRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      <div className="px-4 py-3 border-b border-slate-800 shrink-0">
        <p className="text-sm font-semibold text-slate-300">🔌 Wire</p>
        <p className="text-xs text-slate-500 mt-0.5">What the server sees</p>
      </div>
      <div className="flex-1 overflow-y-auto p-3 space-y-2 min-h-0">
        {events.length === 0 && (
          <p className="text-center text-slate-600 text-xs pt-8">
            Send a message to see encrypted wire data
          </p>
        )}
        {events.map((e) => (
          <div key={e.id} className="bg-slate-800 rounded-lg p-2.5 text-xs font-mono space-y-1">
            <div className="flex items-center justify-between">
              <span className={e.direction === 'sent' ? 'text-blue-400' : 'text-purple-400'}>
                {e.direction === 'sent' ? '↑' : '↓'} {e.from}
              </span>
              <span className="text-slate-600">
                {new Date(e.timestamp).toLocaleTimeString([], { hour12: false })}
              </span>
            </div>
            <div>
              <span className="text-slate-500">ct  </span>
              <span className="text-emerald-400 break-all">{e.ciphertext.slice(0, 28)}…</span>
            </div>
            <div>
              <span className="text-slate-500">n   </span>
              <span className="text-amber-400">{e.nonce.slice(0, 20)}…</span>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── ChatDemo ──────────────────────────────────────────────────────────────────

export default function ChatDemo({ config, sessionId }: Props) {
  const [wireEvents, setWireEvents] = useState<TaggedWireEvent[]>([])

  const aliceId = `alice-${sessionId}`
  const bobId   = `bob-${sessionId}`

  function addWire(e: TaggedWireEvent) {
    setWireEvents((prev) => [...prev.slice(-29), e])
  }

  return (
    <div className="space-y-4 h-full">
      {/* Info banner */}
      <div className="flex gap-2 text-xs text-slate-400 bg-slate-900 rounded-lg px-4 py-3 border border-slate-800">
        <span className="text-blue-400 shrink-0 mt-px">ℹ</span>
        <span>
          Alice and Bob are two independent hook instances running in the same browser tab — simulating
          two users on one device. All encryption happens client-side;
          the <strong className="text-slate-300">Wire</strong> panel shows the encrypted blobs the
          server sees and cannot read.
        </span>
      </div>

      {/* Three-column layout */}
      <div className="grid grid-cols-[1fr_240px_1fr] gap-4" style={{ height: 'calc(100vh - 260px)', minHeight: '400px' }}>
        <ChatPanel
          name="Alice" emoji="👩"
          userId={aliceId} recipientId={bobId}
          config={config} onWire={addWire}
        />
        <WirePanel events={wireEvents} />
        <ChatPanel
          name="Bob" emoji="👨"
          userId={bobId} recipientId={aliceId}
          config={config} onWire={addWire}
        />
      </div>
    </div>
  )
}
