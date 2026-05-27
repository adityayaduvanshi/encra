import { useState, useEffect, useRef, useCallback } from 'react'
import { onLog, type LogEntry, type LogCategory } from '../lib/logger'

// ── Category config ────────────────────────────────────────────────────────────

type FilterId = LogCategory | 'ALL'

const CATS: { id: FilterId; label: string; color: string }[] = [
  { id: 'ALL',       label: 'All',       color: 'var(--text-2)'  },
  { id: 'SYSTEM',    label: 'System',    color: 'var(--text-3)'  },
  { id: 'KEY',       label: 'Key',       color: 'var(--amber)'   },
  { id: 'TRANSPORT', label: 'Transport', color: 'var(--blue)'    },
  { id: 'RATCHET',   label: 'Ratchet',   color: 'var(--purple)'  },
  { id: 'CRYPTO',    label: 'Crypto',    color: 'var(--accent)'  },
  { id: 'ERROR',     label: 'Error',     color: 'var(--red)'     },
]

const ACTOR_COLORS: Record<string, string> = {
  Alice:  'var(--accent)',
  Bob:    'var(--purple)',
  System: 'var(--text-3)',
}

function catColor(cat: LogCategory): string {
  return CATS.find(c => c.id === cat)?.color ?? 'var(--text-3)'
}

function fmtTs(ts: number): string {
  const d = new Date(ts)
  const h  = d.getHours()  .toString().padStart(2, '0')
  const m  = d.getMinutes().toString().padStart(2, '0')
  const s  = d.getSeconds().toString().padStart(2, '0')
  const ms = d.getMilliseconds().toString().padStart(3, '0')
  return `${h}:${m}:${s}.${ms}`
}

// ── Single entry row ───────────────────────────────────────────────────────────

function EntryRow({ entry }: { entry: LogEntry }) {
  const [open, setOpen] = useState(false)
  const has   = (entry.fields?.length ?? 0) > 0
  const cc    = catColor(entry.category)
  const ac    = ACTOR_COLORS[entry.actor] ?? 'var(--text-2)'

  return (
    <div
      onClick={() => has && setOpen(o => !o)}
      style={{
        borderLeft: `2px solid ${cc}`,
        marginBottom: 1,
        background: open ? 'rgba(255,255,255,0.03)' : 'transparent',
        cursor: has ? 'pointer' : 'default',
        transition: 'background 80ms',
        userSelect: 'none',
      }}
    >
      {/* ── Primary row ── */}
      <div style={{
        display: 'flex', alignItems: 'baseline', gap: 0,
        padding: '4px 12px',
      }}>
        {/* timestamp */}
        <span style={{
          fontFamily: 'JetBrains Mono', fontSize: 9,
          color: 'var(--text-3)', flexShrink: 0, width: 88,
        }}>
          {fmtTs(entry.ts)}
        </span>

        {/* category */}
        <span style={{
          fontFamily: 'JetBrains Mono', fontSize: 9,
          color: cc, flexShrink: 0, width: 72,
          textTransform: 'uppercase', letterSpacing: '0.04em',
        }}>
          {entry.category}
        </span>

        {/* actor */}
        <span style={{
          fontFamily: 'JetBrains Mono', fontSize: 9,
          color: ac, flexShrink: 0, width: 48,
        }}>
          {entry.actor}
        </span>

        {/* title */}
        <span style={{
          fontFamily: 'Plus Jakarta Sans', fontSize: 12,
          color: 'var(--text-1)', flex: 1, minWidth: 0,
          lineHeight: 1.4,
        }}>
          {entry.title}
        </span>

        {/* expand chevron */}
        {has && (
          <span style={{
            fontFamily: 'JetBrains Mono', fontSize: 8,
            color: 'var(--text-3)', flexShrink: 0, marginLeft: 8,
            display: 'inline-block',
            transform: open ? 'rotate(90deg)' : 'none',
            transition: 'transform 120ms',
          }}>▶</span>
        )}
      </div>

      {/* ── Detail fields ── */}
      {open && entry.fields && (
        <div style={{
          padding: '2px 12px 8px 210px',
          display: 'flex', flexDirection: 'column', gap: 3,
        }}>
          {entry.fields.map((f, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
              <span style={{
                fontFamily: 'JetBrains Mono', fontSize: 9,
                color: 'var(--text-3)', flexShrink: 0,
                minWidth: 90, textAlign: 'right',
              }}>
                {f.label}
              </span>
              <span style={{
                fontFamily: f.mono === false ? 'Plus Jakarta Sans' : 'JetBrains Mono',
                fontSize: 10, lineHeight: 1.6,
                color: 'var(--text-2)',
                wordBreak: 'break-all',
              }}>
                {f.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Dialog ─────────────────────────────────────────────────────────────────────

interface Props {
  open:    boolean
  onClose: () => void
}

export function LogsDialog({ open, onClose }: Props) {
  const [entries,    setEntries]    = useState<LogEntry[]>([])
  const [filter,     setFilter]     = useState<FilterId>('ALL')
  const [autoScroll, setAutoScroll] = useState(true)
  const bodyRef = useRef<HTMLDivElement>(null)

  // Subscribe to log events
  useEffect(() => {
    return onLog((e) => setEntries(prev => [...prev.slice(-999), e]))
  }, [])

  // Auto-scroll on new entries
  useEffect(() => {
    if (autoScroll && open) {
      const el = bodyRef.current
      if (el) el.scrollTop = el.scrollHeight
    }
  }, [entries, open, autoScroll])

  const handleScroll = useCallback(() => {
    const el = bodyRef.current
    if (!el) return
    setAutoScroll(el.scrollHeight - el.scrollTop - el.clientHeight < 48)
  }, [])

  const filtered = filter === 'ALL' ? entries : entries.filter(e => e.category === filter)

  // Keyboard shortcut: Escape to close
  useEffect(() => {
    if (!open) return
    const fn = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', fn)
    return () => window.removeEventListener('keydown', fn)
  }, [open, onClose])

  if (!open) return null

  const catCount = (id: FilterId) =>
    id === 'ALL' ? entries.length : entries.filter(e => e.category === id).length

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0,
          background: 'rgba(0,0,0,0.5)',
          zIndex: 40,
          backdropFilter: 'blur(2px)',
        }}
      />

      {/* Panel */}
      <div
        style={{
          position: 'fixed', bottom: 0, left: 0, right: 0,
          height: '60vh',
          background: '#0a0a0c',
          border: '1px solid var(--border)',
          borderBottom: 'none',
          borderRadius: '14px 14px 0 0',
          zIndex: 50,
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 -12px 60px rgba(0,0,0,0.6)',
          animation: 'slideUp 200ms cubic-bezier(0.32, 0.72, 0, 1) both',
        }}
      >
        {/* ── Header ── */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 14px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-surface)',
          borderRadius: '14px 14px 0 0',
          flexShrink: 0,
          flexWrap: 'wrap',
          rowGap: 8,
        }}>
          {/* Title */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <div style={{
              width: 6, height: 6, borderRadius: '50%',
              background: 'var(--accent)',
            }} />
            <span style={{
              fontFamily: 'JetBrains Mono', fontSize: 11,
              fontWeight: 600, color: 'var(--text-1)',
            }}>
              Debug Inspector
            </span>
            <span style={{
              fontFamily: 'JetBrains Mono', fontSize: 9,
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              padding: '2px 8px', borderRadius: 99, color: 'var(--text-3)',
            }}>
              {entries.length} events
            </span>
          </div>

          {/* Category filters */}
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {CATS.map(c => {
              const count = catCount(c.id)
              const active = filter === c.id
              return (
                <button
                  key={c.id}
                  onClick={() => setFilter(c.id)}
                  style={{
                    fontFamily: 'JetBrains Mono', fontSize: 9,
                    padding: '3px 8px', borderRadius: 99,
                    background: active ? c.color + '20' : 'transparent',
                    border: `1px solid ${active ? c.color + '60' : 'var(--border)'}`,
                    color: active ? c.color : 'var(--text-3)',
                    cursor: 'pointer',
                    transition: 'all 100ms',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                    display: 'flex', gap: 5, alignItems: 'center',
                  }}
                >
                  {c.label}
                  {count > 0 && (
                    <span style={{
                      background: active ? c.color + '30' : 'var(--bg-elevated)',
                      color: active ? c.color : 'var(--text-3)',
                      padding: '0 4px', borderRadius: 4, fontSize: 8,
                    }}>
                      {count}
                    </span>
                  )}
                </button>
              )
            })}
          </div>

          {/* Right controls */}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
            {!autoScroll && (
              <button
                onClick={() => {
                  setAutoScroll(true)
                  if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight
                }}
                style={{
                  fontFamily: 'JetBrains Mono', fontSize: 9,
                  background: 'var(--accent-dim)', border: '1px solid var(--accent-border)',
                  color: 'var(--accent)', padding: '3px 8px',
                  borderRadius: 99, cursor: 'pointer',
                }}
              >
                ↓ latest
              </button>
            )}
            <button
              onClick={() => { setEntries([]); setAutoScroll(true) }}
              style={{
                fontFamily: 'JetBrains Mono', fontSize: 9,
                color: 'var(--text-3)', background: 'none',
                border: '1px solid var(--border)',
                padding: '3px 8px', borderRadius: 99, cursor: 'pointer',
              }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}
            >
              clear
            </button>
            <button
              onClick={onClose}
              style={{
                width: 24, height: 24, borderRadius: '50%',
                background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                color: 'var(--text-3)', cursor: 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 14, lineHeight: 1,
              }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}
            >
              ×
            </button>
          </div>
        </div>

        {/* ── Column labels ── */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 0,
          padding: '4px 12px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-surface)',
          flexShrink: 0,
        }}>
          {[
            { label: 'time',     w: 90 },
            { label: 'category', w: 74 },
            { label: 'actor',    w: 48 },
            { label: 'event',    w: undefined },
          ].map(col => (
            <span key={col.label} style={{
              fontFamily: 'JetBrains Mono', fontSize: 8,
              color: 'var(--text-3)', textTransform: 'uppercase',
              letterSpacing: '0.06em',
              width: col.w, flex: col.w ? undefined : 1,
              flexShrink: 0,
            }}>
              {col.label}
            </span>
          ))}
        </div>

        {/* ── Log body ── */}
        <div
          ref={bodyRef}
          onScroll={handleScroll}
          style={{ flex: 1, overflowY: 'auto' }}
        >
          {filtered.length === 0 ? (
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              height: '100%', flexDirection: 'column', gap: 8, opacity: 0.35,
            }}>
              <p style={{ fontSize: 26 }}>📋</p>
              <p style={{
                fontFamily: 'JetBrains Mono', fontSize: 10,
                color: 'var(--text-3)',
              }}>
                {entries.length === 0
                  ? 'no events yet — use the playground to generate logs'
                  : 'no entries match this filter'
                }
              </p>
            </div>
          ) : (
            filtered.map(e => <EntryRow key={e.id} entry={e} />)
          )}
        </div>

        {/* ── Footer ── */}
        <div style={{
          padding: '6px 14px',
          borderTop: '1px solid var(--border)',
          flexShrink: 0,
          display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <p style={{
            fontFamily: 'JetBrains Mono', fontSize: 9,
            color: 'var(--text-3)',
          }}>
            click any row to expand details · esc to close
          </p>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 16 }}>
            {CATS.filter(c => c.id !== 'ALL').map(c => (
              <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: c.color, opacity: 0.8 }} />
                <span style={{
                  fontFamily: 'JetBrains Mono', fontSize: 8,
                  color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.04em',
                }}>
                  {c.label}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}
