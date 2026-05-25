import { useState, useMemo, useEffect } from 'react'
import ChatDemo from './components/ChatDemo'
import FileDemo from './components/FileDemo'
import FormDemo from './components/FormDemo'
import { LogsDialog } from './components/LogsDialog'
import { onLog } from './lib/logger'

export interface Config {
  apiKey: string
  serverUrl: string
}

type Tab = 'chat' | 'file' | 'form'

const TABS: { id: Tab; icon: string; label: string; hook: string; desc: string }[] = [
  { id: 'chat', icon: '↔', label: 'Chat',  hook: 'useE2EChat', desc: 'Real-time messaging' },
  { id: 'file', icon: '⊞', label: 'File',  hook: 'useE2EFile', desc: 'File encryption'    },
  { id: 'form', icon: '≡', label: 'Form',  hook: 'useE2EForm', desc: 'Field encryption'   },
]

// ── Sidebar ────────────────────────────────────────────────────────────────────

function Sidebar({
  tab, onTab, sessionId, onConfig, onLogs, unreadLogs,
}: {
  tab: Tab; onTab: (t: Tab) => void; sessionId: string; onConfig: () => void
  onLogs: () => void; unreadLogs: number
}) {
  return (
    <aside
      className="flex flex-col shrink-0 py-4"
      style={{
        width: 200,
        background: 'var(--bg-surface)',
        borderRight: '1px solid var(--border)',
      }}
    >
      {/* Logo */}
      <div className="px-4 mb-6">
        <div className="flex items-center gap-2.5">
          <div
            className="flex items-center justify-center shrink-0"
            style={{
              width: 28, height: 28,
              background: 'var(--accent)',
              borderRadius: 7,
            }}
          >
            <span style={{ fontSize: 14, filter: 'brightness(0)' }}>🔐</span>
          </div>
          <span
            className="mono font-medium tracking-tight"
            style={{ fontSize: 15, color: 'var(--text-1)' }}
          >
            encra
          </span>
        </div>
        <p
          className="mono mt-1"
          style={{ fontSize: 10, color: 'var(--text-3)', paddingLeft: 38 }}
        >
          playground
        </p>
      </div>

      {/* Section label */}
      <p
        className="px-4 mb-1.5 mono uppercase tracking-widest"
        style={{ fontSize: 9, color: 'var(--text-3)' }}
      >
        Hooks
      </p>

      {/* Nav */}
      <nav className="flex-1 px-2 space-y-0.5">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => onTab(t.id)}
            className={`nav-item${tab === t.id ? ' active' : ''}`}
          >
            <span
              className="mono shrink-0"
              style={{
                fontSize: 13,
                color: tab === t.id ? 'var(--accent)' : 'var(--text-3)',
                width: 16,
                textAlign: 'center',
              }}
            >
              {t.icon}
            </span>
            <span style={{ fontSize: 13 }}>{t.label}</span>
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div
        className="mx-4 pt-4"
        style={{ borderTop: '1px solid var(--border)' }}
      >
        <div className="flex items-center justify-between">
          <div>
            <p style={{ fontSize: 10, color: 'var(--text-3)' }}>session</p>
            <p className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>
              {sessionId}
            </p>
          </div>
          <div style={{ display: 'flex', gap: 4 }}>
            {/* Logs button */}
            <button
              onClick={onLogs}
              title="Debug Inspector"
              className="flex items-center justify-center transition-colors"
              style={{
                width: 28, height: 28,
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                borderRadius: 7,
                color: 'var(--text-3)',
                cursor: 'pointer',
                fontSize: 12,
                position: 'relative',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-1)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
            >
              ⊙
              {unreadLogs > 0 && (
                <span style={{
                  position: 'absolute', top: -4, right: -4,
                  background: 'var(--accent)', color: '#000',
                  fontFamily: 'JetBrains Mono', fontSize: 7, fontWeight: 700,
                  minWidth: 14, height: 14, borderRadius: 99,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  padding: '0 3px', lineHeight: 1,
                }}>
                  {unreadLogs > 99 ? '99' : unreadLogs}
                </span>
              )}
            </button>
            {/* Config button */}
            <button
              onClick={onConfig}
              title="Change config"
              className="flex items-center justify-center transition-colors"
              style={{
                width: 28, height: 28,
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                borderRadius: 7,
                color: 'var(--text-3)',
                cursor: 'pointer',
                fontSize: 13,
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-1)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
            >
              ⚙
            </button>
          </div>
        </div>
      </div>
    </aside>
  )
}

// ── Main app ───────────────────────────────────────────────────────────────────

const STORAGE_KEY = 'encra_playground_config'

function loadConfig(): Config | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as unknown
    if (
      parsed &&
      typeof parsed === 'object' &&
      'apiKey' in parsed && typeof (parsed as Config).apiKey === 'string' &&
      'serverUrl' in parsed && typeof (parsed as Config).serverUrl === 'string' &&
      (parsed as Config).apiKey.trim()
    ) return parsed as Config
  } catch { /* ignore */ }
  return null
}

export default function App() {
  const [config,    setConfig]    = useState<Config | null>(loadConfig)
  const [tab,       setTab]       = useState<Tab>('chat')
  const [logsOpen,  setLogsOpen]  = useState(false)
  const [unread,    setUnread]    = useState(0)
  const sessionId = useMemo(() => Math.random().toString(36).slice(2, 7), [])

  // Count new log events while dialog is closed
  useEffect(() => {
    if (logsOpen) return
    return onLog(() => setUnread(n => n + 1))
  }, [logsOpen])

  function openLogs() { setLogsOpen(true); setUnread(0) }

  function saveConfig(c: Config) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(c))
    setConfig(c)
  }

  function clearConfig() {
    localStorage.removeItem(STORAGE_KEY)
    setConfig(null)
  }

  if (!config) return <ConfigScreen onSubmit={saveConfig} />

  const activeTab = TABS.find((t) => t.id === tab)!

  return (
    <div className="flex" style={{ height: '100vh', overflow: 'hidden', background: 'var(--bg)' }}>
      <Sidebar
        tab={tab} onTab={setTab} sessionId={sessionId}
        onConfig={clearConfig}
        onLogs={openLogs} unreadLogs={unread}
      />
      <LogsDialog open={logsOpen} onClose={() => setLogsOpen(false)} />

      <div className="flex flex-col flex-1 min-w-0" style={{ overflow: 'hidden' }}>
        {/* Page header */}
        <div
          className="flex items-center gap-3 shrink-0"
          style={{
            padding: '14px 24px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-surface)',
          }}
        >
          <span className="mono" style={{ color: 'var(--text-3)', fontSize: 13 }}>
            {activeTab.icon}
          </span>
          <h1 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)' }}>
            {activeTab.label}
          </h1>
          <span
            className="mono"
            style={{
              fontSize: 11,
              color: 'var(--accent)',
              background: 'var(--accent-dim)',
              border: '1px solid var(--accent-border)',
              padding: '2px 8px',
              borderRadius: 99,
            }}
          >
            {activeTab.hook}
          </span>
          <span style={{ fontSize: 12, color: 'var(--text-3)', marginLeft: 2 }}>
            {activeTab.desc}
          </span>
        </div>

        {/* Content */}
        <div
          className="flex-1 fade-up"
          key={tab}
          style={{ overflow: 'hidden', padding: 20, display: 'flex', flexDirection: 'column', minHeight: 0 }}
        >
          {tab === 'chat' && <ChatDemo config={config} sessionId={sessionId} />}
          {tab === 'file' && <FileDemo config={config} sessionId={sessionId} />}
          {tab === 'form' && <FormDemo config={config} sessionId={sessionId} />}
        </div>
      </div>
    </div>
  )
}

// ── Config / landing screen ────────────────────────────────────────────────────

function ConfigScreen({ onSubmit }: { onSubmit: (c: Config) => void }) {
  const saved = loadConfig()
  const [apiKey,    setApiKey]    = useState(saved?.apiKey    ?? '')
  const [serverUrl, setServerUrl] = useState(saved?.serverUrl ?? 'https://api.encra.dev')

  const primitives = [
    'X25519 key exchange',
    'XSalsa20-Poly1305',
    'Double Ratchet',
    'Multi-device',
  ]

  return (
    <div
      className="flex items-center justify-center"
      style={{ minHeight: '100vh', background: 'var(--bg)', padding: 24 }}
    >
      <div style={{ width: '100%', maxWidth: 380 }}>
        {/* Brand */}
        <div className="text-center" style={{ marginBottom: 40 }}>
          <div
            className="inline-flex items-center justify-center"
            style={{
              width: 52, height: 52,
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 14,
              marginBottom: 20,
              fontSize: 24,
            }}
          >
            🔐
          </div>
          <h1
            className="mono"
            style={{ fontSize: 26, fontWeight: 500, color: 'var(--text-1)', letterSpacing: '-0.5px' }}
          >
            encra
            <span style={{ color: 'var(--text-3)', fontWeight: 400 }}> playground</span>
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 8, lineHeight: 1.6 }}>
            Signal-level E2E encryption.
            <br />
            Try all three hooks live in your browser.
          </p>
        </div>

        {/* Card */}
        <div className="panel" style={{ padding: 20, marginBottom: 16 }}>
          <div style={{ marginBottom: 14 }}>
            <label
              className="mono"
              style={{
                display: 'block', fontSize: 10,
                color: 'var(--text-3)', marginBottom: 6,
                textTransform: 'uppercase', letterSpacing: '0.08em',
              }}
            >
              API Key
            </label>
            <input
              className="field mono"
              type="text"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="e2e_live_…"
              autoFocus
            />
          </div>

          <div style={{ marginBottom: 20 }}>
            <label
              className="mono"
              style={{
                display: 'block', fontSize: 10,
                color: 'var(--text-3)', marginBottom: 6,
                textTransform: 'uppercase', letterSpacing: '0.08em',
              }}
            >
              Server URL
            </label>
            <input
              className="field mono"
              type="text"
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && apiKey.trim() && onSubmit({ apiKey: apiKey.trim(), serverUrl })}
            />
          </div>

          <button
            className="btn btn-accent"
            style={{ width: '100%', padding: '10px 14px', fontSize: 13 }}
            onClick={() => apiKey.trim() && onSubmit({ apiKey: apiKey.trim(), serverUrl })}
            disabled={!apiKey.trim()}
          >
            Launch playground
            <span style={{ opacity: 0.7 }}>→</span>
          </button>
        </div>

        {/* Primitive chips */}
        <div className="flex flex-wrap justify-center" style={{ gap: 6 }}>
          {primitives.map((p) => (
            <span
              key={p}
              className="mono"
              style={{
                fontSize: 10,
                color: 'var(--text-3)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                padding: '3px 10px',
                borderRadius: 99,
              }}
            >
              {p}
            </span>
          ))}
        </div>

        <p
          className="text-center"
          style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 20 }}
        >
          Get an API key at{' '}
          <a
            href="https://encra.dev"
            target="_blank"
            rel="noreferrer"
            style={{ color: 'var(--accent)' }}
          >
            encra.dev
          </a>
          {' '}— free, no credit card
        </p>
      </div>
    </div>
  )
}
