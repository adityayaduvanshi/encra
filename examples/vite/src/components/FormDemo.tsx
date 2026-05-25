import { useState } from 'react'
import { useE2EForm } from '@encra/react'
import type { EncryptedFields } from '@encra/react'
import type { Config } from '../App'
import { StatusBadge } from './StatusBadge'

interface Props {
  config: Config
  sessionId: string
}

const FORM_FIELDS = [
  { name: 'fullName',       label: 'Full name',       placeholder: 'Alice Johnson',            type: 'text'  },
  { name: 'dateOfBirth',    label: 'Date of birth',   placeholder: '1990-04-15',               type: 'text'  },
  { name: 'ssn',            label: 'SSN',             placeholder: '123-45-6789',              type: 'text'  },
  { name: 'email',          label: 'Email',           placeholder: 'alice@example.com',        type: 'email' },
  { name: 'chiefComplaint', label: 'Chief complaint', placeholder: 'Persistent headaches…',   type: 'text'  },
  { name: 'notes',          label: 'Private notes',   placeholder: 'Anything else…',           type: 'text'  },
] as const

type FieldName = (typeof FORM_FIELDS)[number]['name']

// ── Alice / sender panel ───────────────────────────────────────────────────────

interface AliceProps {
  userId: string
  recipientId: string
  config: Config
  onEncrypted: (ef: EncryptedFields) => void
}

function AlicePanel({ userId, recipientId, config, onEncrypted }: AliceProps) {
  const { encryptFields, isReady, error } = useE2EForm({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [values, setValues] = useState<Record<FieldName, string>>({
    fullName: '', dateOfBirth: '', ssn: '', email: '', chiefComplaint: '', notes: '',
  })
  const [busy, setBusy]  = useState(false)
  const [sent, setSent]  = useState(false)

  function set(name: FieldName, value: string) {
    setValues((v) => ({ ...v, [name]: value }))
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!isReady) return
    setBusy(true)
    try {
      const ef = await encryptFields(
        Object.fromEntries(
          Object.entries(values).filter(([, v]) => v.trim())
        ) as Record<string, string>,
        recipientId,
      )
      onEncrypted(ef)
      setSent(true)
    } catch (err) {
      console.error(err)
    } finally {
      setBusy(false)
    }
  }

  if (sent) {
    return (
      <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <span className="text-xl">👩</span>
            <p className="font-semibold text-slate-100">Alice <span className="text-slate-500 font-normal text-xs">patient</span></p>
          </div>
          <StatusBadge isReady={isReady} isConnecting={false} error={error} />
        </div>
        <div className="flex-1 flex flex-col items-center justify-center gap-4 p-6 text-center">
          <div className="text-5xl">📤</div>
          <p className="text-emerald-400 font-medium">Form submitted (encrypted)</p>
          <p className="text-slate-400 text-sm">The doctor (Bob) received the encrypted payload →</p>
          <button
            onClick={() => setSent(false)}
            className="text-sm text-slate-400 hover:text-slate-200 underline underline-offset-2"
          >
            Fill again
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-xl">👩</span>
          <div>
            <p className="font-semibold text-slate-100 leading-none">Alice <span className="text-slate-500 font-normal text-xs">patient</span></p>
            <p className="text-xs text-slate-500 font-mono mt-0.5 truncate">{userId}</p>
          </div>
        </div>
        <StatusBadge isReady={isReady} isConnecting={false} error={error} />
      </div>

      <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-4 space-y-3 min-h-0">
        <p className="text-xs text-slate-500 uppercase tracking-wide">Medical intake form</p>
        {FORM_FIELDS.map((f) => (
          <div key={f.name}>
            <label className="block text-xs font-medium text-slate-400 mb-1">{f.label}</label>
            <input
              type={f.type}
              value={values[f.name]}
              onChange={(e) => set(f.name, e.target.value)}
              placeholder={f.placeholder}
              disabled={!isReady}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 disabled:opacity-40 focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </div>
        ))}

        {error && (
          <p className="text-xs text-red-400">{error.message}</p>
        )}

        <button
          type="submit"
          disabled={!isReady || busy || Object.values(values).every((v) => !v.trim())}
          className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium rounded-lg transition-colors text-sm"
        >
          {busy ? 'Encrypting…' : '🔒 Submit encrypted'}
        </button>
      </form>
    </div>
  )
}

// ── Bob / recipient panel ─────────────────────────────────────────────────────

interface BobProps {
  userId: string
  senderId: string
  config: Config
  encrypted: EncryptedFields | null
}

function BobPanel({ userId, senderId, config, encrypted }: BobProps) {
  const { decryptFields, isReady, error } = useE2EForm({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [result, setResult] = useState<Record<string, string> | null>(null)
  const [busy,   setBusy]   = useState(false)
  const [decErr, setDecErr] = useState<string | null>(null)

  async function handleDecrypt() {
    if (!encrypted || !isReady) return
    setBusy(true)
    setDecErr(null)
    try {
      const r = await decryptFields(encrypted, senderId)
      setResult(r)
    } catch (err) {
      setDecErr(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-xl">👨‍⚕️</span>
          <div>
            <p className="font-semibold text-slate-100 leading-none">Bob <span className="text-slate-500 font-normal text-xs">doctor</span></p>
            <p className="text-xs text-slate-500 font-mono mt-0.5 truncate">{userId}</p>
          </div>
        </div>
        <StatusBadge isReady={isReady} isConnecting={false} error={error} />
      </div>

      <div className="flex-1 overflow-y-auto p-4 min-h-0">
        {result ? (
          <div className="space-y-3">
            <p className="text-xs text-slate-500 uppercase tracking-wide">Decrypted patient record</p>
            {Object.entries(result).map(([key, value]) => {
              const field = FORM_FIELDS.find((f) => f.name === key)
              return (
                <div key={key}>
                  <p className="text-xs text-slate-500 mb-0.5">{field?.label ?? key}</p>
                  <p className="text-sm text-slate-100 bg-slate-800 rounded-lg px-3 py-2 font-mono">
                    {value}
                  </p>
                </div>
              )
            })}
            <button
              onClick={() => setResult(null)}
              className="text-xs text-slate-500 hover:text-slate-300 underline underline-offset-2 mt-2"
            >
              Reset
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
            {!encrypted ? (
              <div className="space-y-2">
                <div className="text-4xl opacity-30">📭</div>
                <p className="text-slate-600 text-sm">Waiting for Alice to submit a form…</p>
              </div>
            ) : (
              <div className="space-y-4 w-full">
                <div className="bg-slate-800 rounded-lg px-4 py-3 text-left space-y-1">
                  <p className="text-xs text-slate-500 uppercase tracking-wide mb-2">Incoming encrypted form</p>
                  <p className="text-xs text-slate-400">
                    {encrypted.devices.length} device envelope(s) ·{' '}
                    {Object.keys(encrypted.devices[0]?.fields ?? {}).length} field(s)
                  </p>
                </div>
                <button
                  onClick={handleDecrypt}
                  disabled={!isReady || busy}
                  className="w-full py-2.5 bg-purple-700 hover:bg-purple-600 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium rounded-lg transition-colors text-sm"
                >
                  {busy ? 'Decrypting…' : '🔓 Decrypt fields'}
                </button>
                {decErr && <p className="text-xs text-red-400">{decErr}</p>}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Wire panel ─────────────────────────────────────────────────────────────────

function WirePanel({ encrypted }: { encrypted: EncryptedFields | null }) {
  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      <div className="px-4 py-3 border-b border-slate-800 shrink-0">
        <p className="text-sm font-semibold text-slate-300">🔌 Wire</p>
        <p className="text-xs text-slate-500 mt-0.5">EncryptedFields payload</p>
      </div>
      <div className="flex-1 overflow-y-auto p-3 min-h-0">
        {!encrypted ? (
          <p className="text-center text-slate-600 text-xs pt-8">
            Submit the form to see the payload
          </p>
        ) : (
          <div className="text-xs font-mono space-y-2 text-slate-400">
            <p className="text-slate-500 uppercase tracking-wide text-[10px]">
              devices ({encrypted.devices.length})
            </p>
            {encrypted.devices.map((dev, i) => (
              <div key={i} className="bg-slate-800 rounded-lg p-2 space-y-2">
                <p>
                  <span className="text-slate-500">deviceId </span>
                  <span className="text-blue-400">{dev.deviceId}</span>
                </p>
                <p className="text-slate-500 text-[10px] uppercase tracking-wide">fields</p>
                {Object.entries(dev.fields).map(([key, { ciphertext, nonce }]) => (
                  <div key={key} className="pl-2 border-l border-slate-700 space-y-0.5">
                    <p className="text-slate-300">{key}</p>
                    <p>
                      <span className="text-slate-500">ct  </span>
                      <span className="text-emerald-400 break-all">{ciphertext.slice(0, 20)}…</span>
                    </p>
                    <p>
                      <span className="text-slate-500">n   </span>
                      <span className="text-amber-400">{nonce.slice(0, 16)}…</span>
                    </p>
                  </div>
                ))}
              </div>
            ))}
            <p className="text-slate-600 text-[10px] leading-relaxed pt-1">
              Field <em>names</em> are visible; field <em>values</em> are
              encrypted with unique nonces — your DB stores only ciphertext.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// ── FormDemo ──────────────────────────────────────────────────────────────────

export default function FormDemo({ config, sessionId }: Props) {
  const [encrypted, setEncrypted] = useState<EncryptedFields | null>(null)

  const aliceId = `alice-form-${sessionId}`
  const bobId   = `bob-form-${sessionId}`

  return (
    <div className="space-y-4 h-full">
      <div className="flex gap-2 text-xs text-slate-400 bg-slate-900 rounded-lg px-4 py-3 border border-slate-800">
        <span className="text-blue-400 shrink-0 mt-px">ℹ</span>
        <span>
          Alice (patient) fills in a HIPAA intake form and encrypts it for Bob (doctor).
          The <strong className="text-slate-300">Wire</strong> panel shows what gets stored on the server —
          field names in plaintext, field <em>values</em> as ciphertext. Only Bob's private key can decrypt.
        </span>
      </div>

      <div className="grid grid-cols-[1fr_240px_1fr] gap-4" style={{ height: 'calc(100vh - 260px)', minHeight: '500px' }}>
        <AlicePanel
          userId={aliceId} recipientId={bobId}
          config={config} onEncrypted={setEncrypted}
        />
        <WirePanel encrypted={encrypted} />
        <BobPanel
          userId={bobId} senderId={aliceId}
          config={config} encrypted={encrypted}
        />
      </div>
    </div>
  )
}
