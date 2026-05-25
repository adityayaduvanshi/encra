import { useState, useMemo } from 'react'
import ChatDemo from './components/ChatDemo'
import FileDemo from './components/FileDemo'
import FormDemo from './components/FormDemo'

export interface Config {
  apiKey: string
  serverUrl: string
}

type Tab = 'chat' | 'file' | 'form'

const TABS: { id: Tab; label: string; icon: string; hook: string }[] = [
  { id: 'chat', label: 'Chat',  icon: '💬', hook: 'useE2EChat' },
  { id: 'file', label: 'File',  icon: '📁', hook: 'useE2EFile' },
  { id: 'form', label: 'Form',  icon: '📋', hook: 'useE2EForm' },
]

export default function App() {
  const [config, setConfig] = useState<Config | null>(null)
  const [tab, setTab]       = useState<Tab>('chat')

  // Stable session suffix — keeps userIds unique per browser session
  // so demo users don't collide with other people testing at the same time
  const sessionId = useMemo(() => Math.random().toString(36).slice(2, 7), [])

  if (!config) return <ConfigScreen onSubmit={setConfig} />

  return (
    <div className="min-h-screen flex flex-col">
      {/* ── Header ── */}
      <header className="border-b border-slate-800 px-6 py-3 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🔐</span>
          <div>
            <h1 className="font-bold text-slate-100 leading-none">Encra Playground</h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Signal-level E2E encryption — try it live
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-slate-600 font-mono hidden sm:block">
            session·{sessionId}
          </span>
          <button
            onClick={() => setConfig(null)}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors px-3 py-1.5 rounded-md border border-slate-700 hover:border-slate-500"
          >
            ⚙ Config
          </button>
        </div>
      </header>

      {/* ── Tab bar ── */}
      <div className="border-b border-slate-800 px-6 shrink-0">
        <nav className="flex gap-1 -mb-px">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors border-b-2 ${
                tab === t.id
                  ? 'text-emerald-400 border-emerald-400'
                  : 'text-slate-400 border-transparent hover:text-slate-200 hover:border-slate-600'
              }`}
            >
              <span>{t.icon}</span>
              <span className="hidden sm:inline">{t.label}</span>
              <code className="text-xs opacity-60 hidden md:inline">{t.hook}</code>
            </button>
          ))}
        </nav>
      </div>

      {/* ── Content ── */}
      <main className="flex-1 p-6 overflow-auto">
        {tab === 'chat' && <ChatDemo config={config} sessionId={sessionId} />}
        {tab === 'file' && <FileDemo config={config} sessionId={sessionId} />}
        {tab === 'form' && <FormDemo config={config} sessionId={sessionId} />}
      </main>
    </div>
  )
}

// ── Config / landing screen ─────────────────────────────────────────────────

function ConfigScreen({ onSubmit }: { onSubmit: (c: Config) => void }) {
  const [apiKey,    setApiKey]    = useState('')
  const [serverUrl, setServerUrl] = useState('https://api.encra.dev')

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo / headline */}
        <div className="text-center mb-8">
          <div className="text-6xl mb-4">🔐</div>
          <h1 className="text-3xl font-bold text-slate-100">Encra Playground</h1>
          <p className="text-slate-400 mt-2 text-sm leading-relaxed">
            Try <code className="text-emerald-400">useE2EChat</code>,{' '}
            <code className="text-emerald-400">useE2EFile</code>, and{' '}
            <code className="text-emerald-400">useE2EForm</code> live — with real
            encryption running in your browser.
          </p>
        </div>

        {/* Card */}
        <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">
              API Key
            </label>
            <input
              type="text"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="e2e_live_…"
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2.5 text-sm font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">
              Server URL
            </label>
            <input
              type="text"
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </div>
          <button
            onClick={() => apiKey.trim() && onSubmit({ apiKey: apiKey.trim(), serverUrl: serverUrl.trim() })}
            disabled={!apiKey.trim()}
            className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-semibold rounded-lg py-2.5 transition-colors"
          >
            Launch Playground →
          </button>
        </div>

        {/* Feature pills */}
        <div className="flex flex-wrap justify-center gap-2 mt-6">
          {[
            'X25519 key exchange',
            'XSalsa20-Poly1305',
            'Double Ratchet',
            'Multi-device',
            'Zero server trust',
          ].map((f) => (
            <span
              key={f}
              className="text-xs px-2.5 py-1 rounded-full bg-slate-900 text-slate-400 border border-slate-800"
            >
              {f}
            </span>
          ))}
        </div>

        <p className="text-center text-xs text-slate-600 mt-4">
          Need an API key?{' '}
          <a
            href="https://encra.dev"
            target="_blank"
            rel="noreferrer"
            className="text-emerald-500 hover:underline"
          >
            encra.dev
          </a>{' '}
          — free tier, no credit card
        </p>
      </div>
    </div>
  )
}
