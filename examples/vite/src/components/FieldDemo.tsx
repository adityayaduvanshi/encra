import { useState } from 'react'
import { useE2EField } from '@encra/react'
import type { EncryptedField } from '@encra/react'
import { StatusDot } from './StatusBadge'
import { emitLog } from '../lib/logger'

interface Props { sessionId: string }

const FIELD_PRESETS = [
  { label: 'SSN',         placeholder: '123-45-6789'         },
  { label: 'Credit Card', placeholder: '4111 1111 1111 1111' },
  { label: 'Email',       placeholder: 'alice@example.com'   },
  { label: 'Custom',      placeholder: 'any sensitive value…' },
] as const

// ── Left panel — YOU TYPE ─────────────────────────────────────────────────────

function EncryptPanel({
  isReady, preset, onPreset, onEncrypt,
}: {
  isReady: boolean
  preset: number
  onPreset: (i: number) => void
  onEncrypt: (value: string) => Promise<void>
}) {
  const [value,   setValue]   = useState('')
  const [busy,    setBusy]    = useState(false)
  const [encErr,  setEncErr]  = useState<string | null>(null)

  async function handleEncrypt() {
    if (!value.trim() || !isReady) return
    setBusy(true); setEncErr(null)
    try {
      await onEncrypt(value.trim())
    } catch (err) {
      setEncErr(err instanceof Error ? err.message : 'Encryption failed')
    } finally {
      setBusy(false)
    }
  }

  const currentPreset = FIELD_PRESETS[preset]!

  return (
    <div className="panel flex flex-col" style={{ flex: 1, minWidth: 0 }}>
      <div className="panel-header">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center justify-center shrink-0 mono font-medium"
            style={{ width: 26, height: 26, borderRadius: 6, background: 'var(--accent-dim)', border: '1px solid var(--accent-border)', fontSize: 11, color: 'var(--accent)' }}>
            E
          </div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', lineHeight: 1 }}>Encrypt</p>
            <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>local only</p>
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={!isReady} error={null} />
      </div>
      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, flex: 1 }}>

      <div>
        <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Field type
        </p>
        <div className="flex flex-wrap" style={{ gap: 6 }}>
          {FIELD_PRESETS.map((p, i) => (
            <button
              key={p.label}
              onClick={() => { onPreset(i); setValue('') }}
              className="mono"
              style={{
                fontSize: 11, padding: '3px 10px', borderRadius: 99,
                border: `1px solid ${preset === i ? 'var(--accent)' : 'var(--border)'}`,
                background: preset === i ? 'var(--accent-dim)' : 'var(--bg-elevated)',
                color: preset === i ? 'var(--accent)' : 'var(--text-2)', cursor: 'pointer',
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ flex: 1 }}>
        <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Value
        </p>
        <input
          className="field mono"
          style={{ width: '100%', fontSize: 13 }}
          placeholder={currentPreset.placeholder}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleEncrypt()}
          disabled={!isReady || busy}
        />
      </div>

      {encErr && <p style={{ fontSize: 11, color: 'var(--red)' }}>{encErr}</p>}

      <button
        className="btn btn-accent mono"
        style={{ fontSize: 12, padding: '8px 12px' }}
        onClick={handleEncrypt}
        disabled={!isReady || !value.trim() || busy}
      >
        {busy ? 'Encrypting…' : 'Encrypt →'}
      </button>
      </div>
    </div>
  )
}

// ── Center panel — db_record.json ────────────────────────────────────────────

function ServerPanel({ encrypted, fieldLabel }: { encrypted: EncryptedField | null; fieldLabel: string }) {
  const key = fieldLabel.toLowerCase().replace(/\s+/g, '_')

  return (
    <div className="terminal" style={{ flex: 1, minWidth: 0 }}>
      {/* Terminal chrome */}
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: '#ff5f57' }} />
        <div className="terminal-dot" style={{ background: '#febc2e' }} />
        <div className="terminal-dot" style={{ background: '#28c840' }} />
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 8 }}>
          db_record.json
        </span>
      </div>

      <div className="terminal-body">
        {encrypted ? (
          <div>
            <span style={{ color: 'var(--text-3)' }}>{'{'}</span>
            <div style={{ paddingLeft: 16 }}>
              <span style={{ color: 'var(--blue)' }}>"{key}"</span>
              <span style={{ color: 'var(--text-3)' }}>: {'{'}</span>
              <div style={{ paddingLeft: 16 }}>
                <div>
                  <span style={{ color: 'var(--text-3)' }}>"ciphertext": </span>
                  <span style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>
                    "{encrypted.ciphertext.slice(0, 32)}<span style={{ color: 'var(--text-3)' }}>…</span>"
                  </span>
                </div>
                <div style={{ marginTop: 2 }}>
                  <span style={{ color: 'var(--text-3)' }}>"nonce": </span>
                  <span style={{ color: 'var(--amber)', wordBreak: 'break-all' }}>
                    "{encrypted.nonce.slice(0, 22)}<span style={{ color: 'var(--text-3)' }}>…</span>"
                  </span>
                </div>
              </div>
              <span style={{ color: 'var(--text-3)' }}>{'}'}</span>
            </div>
            <span style={{ color: 'var(--text-3)' }}>{'}'}</span>
          </div>
        ) : (
          <div className="flex items-center justify-center" style={{ height: 120 }}>
            <p style={{ color: 'var(--text-3)', fontSize: 10 }}>
              encrypt a value to see db record
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Right panel — YOU READ BACK ───────────────────────────────────────────────

function DecryptPanel({
  isReady, encrypted, onDecrypt, exportKey, onSetKey,
}: {
  isReady: boolean
  encrypted: EncryptedField | null
  onDecrypt: () => Promise<string>
  exportKey: () => string | null
  onSetKey: (b64: string) => Promise<void>
}) {
  const [decrypted,  setDecrypted]  = useState<string | null>(null)
  const [busy,       setBusy]       = useState(false)
  const [decErr,     setDecErr]     = useState<string | null>(null)
  const [copied,     setCopied]     = useState(false)
  const [restoreKey, setRestoreKey] = useState('')
  const [restoreErr, setRestoreErr] = useState<string | null>(null)
  const [restored,   setRestored]   = useState(false)

  async function handleDecrypt() {
    if (!encrypted || !isReady) return
    setBusy(true); setDecErr(null)
    try {
      const plain = await onDecrypt()
      setDecrypted(plain)
    } catch (err) {
      setDecErr(err instanceof Error ? err.message : 'Decryption failed')
    } finally {
      setBusy(false)
    }
  }

  function handleCopy() {
    const key = exportKey()
    if (!key) return
    void navigator.clipboard.writeText(key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  async function handleRestore() {
    if (!restoreKey.trim()) return
    setRestoreErr(null); setRestored(false)
    try {
      await onSetKey(restoreKey.trim())
      setRestored(true); setRestoreKey(''); setDecrypted(null)
    } catch (err) {
      setRestoreErr(err instanceof Error ? err.message : 'Invalid key')
    }
  }

  const exportedKey = exportKey()

  return (
    <div className="panel flex flex-col" style={{ flex: 1, minWidth: 0 }}>
      <div className="panel-header">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center justify-center shrink-0 mono font-medium"
            style={{ width: 26, height: 26, borderRadius: 6, background: 'var(--accent-dim)', border: '1px solid var(--accent-border)', fontSize: 11, color: 'var(--accent)' }}>
            D
          </div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', lineHeight: 1 }}>Decrypt</p>
            <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>your device</p>
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={!isReady} error={null} />
      </div>
      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, flex: 1 }}>

      <div style={{ flex: 1 }}>
        {decrypted !== null ? (
          <div className="mono" style={{ fontSize: 16, color: 'var(--accent)', background: 'var(--accent-dim)', border: '1px solid var(--accent-border)', borderRadius: 6, padding: '10px 12px' }}>
            {decrypted}
          </div>
        ) : (
          <div className="flex items-center justify-center" style={{ minHeight: 52, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-elevated)' }}>
            <p className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
              {encrypted ? 'Click Decrypt to read' : 'Waiting for encrypted value…'}
            </p>
          </div>
        )}
        {decErr && <p style={{ fontSize: 11, color: 'var(--red)', marginTop: 6 }}>{decErr}</p>}
      </div>

      <button
        className="btn mono"
        style={{ fontSize: 12, padding: '7px 12px', border: '1px solid var(--border)', background: 'var(--bg-elevated)', color: 'var(--text-1)' }}
        onClick={handleDecrypt}
        disabled={!isReady || !encrypted || busy}
      >
        {busy ? 'Decrypting…' : 'Decrypt'}
      </button>

      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 10 }}>
        {exportedKey && (
          <div>
            <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Your Key — back this up
            </p>
            <div style={{ display: 'flex', gap: 6 }}>
              <div className="mono" style={{ flex: 1, fontSize: 10, color: 'var(--text-2)', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 8px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {exportedKey}
              </div>
              <button
                className="btn mono"
                style={{ fontSize: 11, padding: '5px 10px', border: '1px solid var(--border)', background: copied ? 'var(--accent-dim)' : 'var(--bg-elevated)', color: copied ? 'var(--accent)' : 'var(--text-2)', flexShrink: 0 }}
                onClick={handleCopy}
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        <div>
          <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Restore from backup
          </p>
          <input
            className="field mono"
            style={{ width: '100%', fontSize: 11, marginBottom: 6 }}
            placeholder="paste base64 key here…"
            value={restoreKey}
            onChange={(e) => setRestoreKey(e.target.value)}
          />
          {restored && <p style={{ fontSize: 11, color: 'var(--accent)', marginBottom: 6 }}>Key restored.</p>}
          {restoreErr && <p style={{ fontSize: 11, color: 'var(--red)', marginBottom: 6 }}>{restoreErr}</p>}
          <button
            className="btn mono"
            style={{ fontSize: 11, padding: '6px 10px', border: '1px solid var(--border)', background: 'var(--bg-elevated)', color: 'var(--text-2)', width: '100%' }}
            onClick={handleRestore}
            disabled={!restoreKey.trim()}
          >
            Restore Key
          </button>
        </div>
      </div>
      </div>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function FieldDemo({ sessionId }: Props) {
  const userId = `field-${sessionId}`
  const { encrypt, decrypt, isReady, error, exportKey, setKey } = useE2EField({ userId })
  const [encrypted,  setEncrypted]  = useState<EncryptedField | null>(null)
  const [preset,     setPreset]     = useState(0)
  const fieldLabel = FIELD_PRESETS[preset]?.label ?? 'value'

  async function handleEncrypt(value: string) {
    const result = await encrypt(value)
    setEncrypted(result)
    emitLog({
      category: 'KEY', actor: 'Field',
      title: 'Value encrypted with XSalsa20-Poly1305',
      fields: [
        { label: 'algorithm',  value: 'XSalsa20-Poly1305 (crypto_secretbox_easy)' },
        { label: 'key type',   value: '32-byte symmetric — never leaves device'   },
        { label: 'ciphertext', value: result.ciphertext.slice(0, 44) + '…'        },
        { label: 'nonce',      value: result.nonce.slice(0, 28) + '…'             },
        { label: 'server sees', value: 'ciphertext + nonce only — cannot decrypt' },
      ],
    })
  }

  if (error) return <div style={{ padding: 24, color: 'var(--red)', fontSize: 13 }}>Error: {error.message}</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, flex: 1, minHeight: 0 }}>
      {/* Info banner */}
      <div className="info-banner">
        <span style={{ color: 'var(--accent)', flexShrink: 0 }}>ℹ</span>
        <span>
          Encrypt individual string values with{' '}
          <span className="mono" style={{ color: 'var(--text-1)' }}>XSalsa20-Poly1305</span>.
          The <span style={{ color: 'var(--text-1)', fontWeight: 500 }}>db_record.json</span> panel
          shows what your database stores — ciphertext only, never plaintext. No server needed.
        </span>
      </div>

      {/* Three panels */}
      <div className="flex" style={{ gap: 12, flex: 1, minHeight: 0, alignItems: 'stretch' }}>
        <EncryptPanel isReady={isReady} preset={preset} onPreset={setPreset} onEncrypt={handleEncrypt} />
        <ServerPanel encrypted={encrypted} fieldLabel={fieldLabel} />
        <DecryptPanel
          isReady={isReady}
          encrypted={encrypted}
          onDecrypt={() => {
            if (!encrypted) return Promise.reject(new Error('Nothing to decrypt.'))
            return decrypt(encrypted)
          }}
          exportKey={exportKey}
          onSetKey={setKey}
        />
      </div>
    </div>
  )
}
