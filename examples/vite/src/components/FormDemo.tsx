import { useState, useEffect, useRef } from 'react'
import { useE2EForm } from '@encra/react'
import type { EncryptedFields } from '@encra/react'
import type { Config } from '../App'
import { StatusDot } from './StatusBadge'
import { emitLog } from '../lib/logger'

interface Props { config: Config; sessionId: string }

const FIELDS = [
  { name: 'fullName',       label: 'Full name',      placeholder: 'Alice Johnson'          },
  { name: 'dateOfBirth',    label: 'Date of birth',  placeholder: '1990-04-15'             },
  { name: 'ssn',            label: 'SSN',            placeholder: '123-45-6789'            },
  { name: 'email',          label: 'Email',          placeholder: 'alice@example.com'      },
  { name: 'chiefComplaint', label: 'Chief complaint',placeholder: 'Persistent headaches…'  },
  { name: 'notes',          label: 'Private notes',  placeholder: 'Anything else…'         },
] as const
type FieldName = (typeof FIELDS)[number]['name']

// ── Alice panel ────────────────────────────────────────────────────────────────

function AlicePanel({
  userId, recipientId, config, onEncrypted,
}: {
  userId: string; recipientId: string; config: Config; onEncrypted: (ef: EncryptedFields) => void
}) {
  const { encryptFields, isReady, error } = useE2EForm({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [values, setValues] = useState<Record<FieldName, string>>({
    fullName: '', dateOfBirth: '', ssn: '', email: '', chiefComplaint: '', notes: '',
  })
  const [busy,   setBusy]   = useState(false)
  const [sent,   setSent]   = useState(false)
  const [encErr, setEncErr] = useState<string | null>(null)
  const didLogRef = useRef(false)

  useEffect(() => {
    if (isReady && !didLogRef.current) {
      didLogRef.current = true
      emitLog({
        category: 'KEY', actor: 'Alice',
        title: 'X25519 key pair registered (form hook)',
        fields: [
          { label: 'userId',      value: userId                         },
          { label: 'algorithm',   value: 'X25519 (Curve25519 ECDH)'     },
          { label: 'private key', value: 'stays on device — never sent' },
        ],
      })
    }
  }, [isReady, userId])

  useEffect(() => {
    if (error) emitLog({ category: 'ERROR', actor: 'Alice', title: error.message })
  }, [error])

  const hasAny = Object.values(values).some((v) => v.trim())

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!isReady) return
    setBusy(true); setEncErr(null)

    const filled = Object.entries(values).filter(([, v]) => v.trim())

    emitLog({
      category: 'KEY', actor: 'Alice',
      title: 'Fetching recipient device public keys',
      fields: [
        { label: 'for',      value: recipientId           },
        { label: 'endpoint', value: 'GET /v1/keys/:userId' },
      ],
    })
    emitLog({
      category: 'CRYPTO', actor: 'Alice',
      title: `Encrypting ${filled.length} form field(s) individually`,
      fields: [
        { label: 'fields',       value: filled.map(([k]) => k).join(', ')                },
        { label: 'algorithm',    value: 'X25519 ECDH + XSalsa20-Poly1305 per field'      },
        { label: 'per-field nonce', value: 'random 24 bytes each (libsodium randombytes)' },
        { label: 'field names',  value: 'plaintext (visible in payload)'                 },
        { label: 'field values', value: 'encrypted — server sees only ciphertext'        },
      ],
    })

    try {
      const ef = await encryptFields(
        Object.fromEntries(filled) as Record<string, string>,
        recipientId,
      )

      emitLog({
        category: 'CRYPTO', actor: 'Alice',
        title: `${filled.length} field(s) encrypted for ${ef.devices.length} device(s)`,
        fields: filled.map(([k]) => ({
          label: k,
          value: (ef.devices[0]?.fields[k]?.ciphertext.slice(0, 26) ?? '?') + '… (ciphertext)',
        })),
      })
      emitLog({
        category: 'TRANSPORT', actor: 'Alice',
        title: 'Encrypted form payload ready for transit',
        fields: [
          { label: 'devices',  value: ef.devices.length.toString()   },
          { label: 'fields',   value: Object.keys(ef.devices[0]?.fields ?? {}).length.toString() },
          { label: 'format',   value: '{ devices: [{ deviceId, fields: { [name]: { ciphertext, nonce } } }] }' },
          { label: 'plaintext','value': '(zero-knowledge — never leaves client)' },
        ],
      })

      onEncrypted(ef); setSent(true)
    } catch (err) {
      emitLog({
        category: 'ERROR', actor: 'Alice',
        title: 'Form encryption failed',
        fields: [{ label: 'error', value: err instanceof Error ? err.message : String(err) }],
      })
      setEncErr(err instanceof Error ? err.message : String(err))
    } finally { setBusy(false) }
  }

  if (sent) return (
    <div className="panel flex flex-col items-center justify-center" style={{ height: '100%', gap: 12, padding: 24 }}>
      <div style={{
        width: 48, height: 48, borderRadius: 12,
        background: 'var(--accent-dim)', border: '1px solid var(--accent-border)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22,
      }}>✓</div>
      <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>Form submitted (encrypted)</p>
      <p style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center' }}>
        Bob (doctor) received the encrypted payload →
      </p>
      <button className="btn btn-ghost" style={{ marginTop: 4 }} onClick={() => setSent(false)}>
        Fill again
      </button>
    </div>
  )

  return (
    <div className="panel flex flex-col" style={{ height: '100%' }}>
      <div className="panel-header">
        <div className="flex items-center gap-2.5">
          <div style={{
            width: 26, height: 26, borderRadius: 6,
            background: 'var(--accent-dim)', border: '1px solid var(--accent-border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, color: 'var(--accent)', fontFamily: 'JetBrains Mono', fontWeight: 500,
          }}>A</div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, lineHeight: 1 }}>Alice</p>
            <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>patient</p>
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={false} error={error} />
      </div>

      <form
        onSubmit={handleSubmit}
        className="flex-1 overflow-y-auto"
        style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}
      >
        <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>
          Medical intake form
        </p>

        {FIELDS.map((f) => (
          <div key={f.name}>
            <label className="mono" style={{
              display: 'block', fontSize: 9,
              color: 'var(--text-3)', marginBottom: 4,
              textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>
              {f.label}
            </label>
            <input
              className="field"
              type="text"
              value={values[f.name]}
              onChange={(e) => setValues((v) => ({ ...v, [f.name]: e.target.value }))}
              placeholder={f.placeholder}
              disabled={!isReady}
            />
          </div>
        ))}

        {encErr && <p className="mono" style={{ fontSize: 11, color: 'var(--red)' }}>{encErr}</p>}

        <button
          type="submit"
          className="btn btn-accent"
          style={{ width: '100%', marginTop: 4 }}
          disabled={!isReady || busy || !hasAny}
        >
          {busy ? 'Encrypting…' : '🔒 Submit encrypted'}
        </button>
      </form>
    </div>
  )
}

// ── Bob panel ──────────────────────────────────────────────────────────────────

function BobPanel({
  userId, senderId, config, encrypted,
}: {
  userId: string; senderId: string; config: Config; encrypted: EncryptedFields | null
}) {
  const { decryptFields, isReady, error } = useE2EForm({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [result, setResult] = useState<Record<string, string> | null>(null)
  const [busy,   setBusy]   = useState(false)
  const [decErr, setDecErr] = useState<string | null>(null)
  const didLogRef = useRef(false)

  useEffect(() => {
    if (isReady && !didLogRef.current) {
      didLogRef.current = true
      emitLog({
        category: 'KEY', actor: 'Bob',
        title: 'X25519 key pair registered (form hook)',
        fields: [
          { label: 'userId',      value: userId                         },
          { label: 'algorithm',   value: 'X25519 (Curve25519 ECDH)'     },
          { label: 'private key', value: 'stays on device — never sent' },
        ],
      })
    }
  }, [isReady, userId])

  useEffect(() => {
    if (error) emitLog({ category: 'ERROR', actor: 'Bob', title: error.message })
  }, [error])

  async function handleDecrypt() {
    if (!encrypted || !isReady) return
    setBusy(true); setDecErr(null)

    const fieldNames = Object.keys(encrypted.devices[0]?.fields ?? {})
    emitLog({
      category: 'KEY', actor: 'Bob',
      title: 'Locating own device envelope in payload',
      fields: [
        { label: 'envelopes', value: encrypted.devices.length.toString()         },
        { label: 'action',    value: 'matching deviceId → ECDH with Alice pubkey' },
      ],
    })
    emitLog({
      category: 'CRYPTO', actor: 'Bob',
      title: `Decrypting ${fieldNames.length} field(s)`,
      fields: [
        { label: 'from',      value: senderId                                          },
        { label: 'algorithm', value: 'X25519 ECDH + XSalsa20-Poly1305 decrypt per field' },
        { label: 'fields',    value: fieldNames.join(', ')                             },
        { label: 'mac check', value: 'Poly1305 MAC verified per field before decryption' },
      ],
    })

    try {
      const result = await decryptFields(encrypted, senderId)
      emitLog({
        category: 'CRYPTO', actor: 'Bob',
        title: `${Object.keys(result).length} field(s) decrypted successfully`,
        fields: Object.entries(result).map(([k, v]) => ({
          label: k,
          value: v,
          mono: false,
        })),
      })
      setResult(result)
    } catch (e) {
      emitLog({
        category: 'ERROR', actor: 'Bob',
        title: 'Form decryption failed',
        fields: [{ label: 'error', value: e instanceof Error ? e.message : String(e) }],
      })
      setDecErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  return (
    <div className="panel flex flex-col" style={{ height: '100%' }}>
      <div className="panel-header">
        <div className="flex items-center gap-2.5">
          <div style={{
            width: 26, height: 26, borderRadius: 6,
            background: 'var(--purple-dim)', border: '1px solid rgba(168,85,247,0.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, color: 'var(--purple)', fontFamily: 'JetBrains Mono', fontWeight: 500,
          }}>B</div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, lineHeight: 1 }}>Bob</p>
            <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>doctor</p>
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={false} error={error} />
      </div>

      <div className="flex-1 overflow-y-auto" style={{ padding: 16 }}>
        {result ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <p className="mono" style={{ fontSize: 9, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>
              ✓ Decrypted patient record
            </p>
            {Object.entries(result).map(([key, value]) => {
              const field = FIELDS.find((f) => f.name === key)
              return (
                <div key={key}>
                  <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                    {field?.label ?? key}
                  </p>
                  <div style={{
                    background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                    borderRadius: 7, padding: '8px 12px',
                    fontSize: 13, fontWeight: 500, color: 'var(--text-1)',
                  }}>
                    {value}
                  </div>
                </div>
              )
            })}
            <button
              className="mono"
              style={{ fontSize: 10, color: 'var(--text-3)', background: 'none', border: 'none', cursor: 'pointer', marginTop: 4, textAlign: 'left' }}
              onClick={() => setResult(null)}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-2)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
            >
              reset
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center" style={{ height: '100%', gap: 12 }}>
            {!encrypted ? (
              <div style={{ textAlign: 'center', opacity: 0.4 }}>
                <p style={{ fontSize: 28, marginBottom: 8 }}>📭</p>
                <p className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
                  waiting for Alice…
                </p>
              </div>
            ) : (
              <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                  borderRadius: 8, padding: '12px 14px',
                }}>
                  <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
                    Incoming encrypted form
                  </p>
                  <p className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>
                    {encrypted.devices.length} device envelope(s)
                  </p>
                  <p className="mono" style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 2 }}>
                    {Object.keys(encrypted.devices[0]?.fields ?? {}).length} field(s)
                  </p>
                </div>
                <button
                  className="btn btn-purple" style={{ width: '100%' }}
                  onClick={handleDecrypt}
                  disabled={!isReady || busy}
                >
                  {busy ? 'Decrypting…' : '🔓 Decrypt fields'}
                </button>
                {decErr && <p className="mono" style={{ fontSize: 11, color: 'var(--red)' }}>{decErr}</p>}
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
    <div className="terminal">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: '#ff5f57' }} />
        <div className="terminal-dot" style={{ background: '#febc2e' }} />
        <div className="terminal-dot" style={{ background: '#28c840' }} />
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 8 }}>
          payload.json
        </span>
      </div>
      <div className="terminal-body">
        {!encrypted ? (
          <p style={{ color: 'var(--text-3)', fontSize: 10 }}>
            submit the form to see payload
          </p>
        ) : (
          <>
            <div style={{ color: 'var(--border-strong)' }}>{'{'}</div>
            <div style={{ paddingLeft: 14 }}>
              <div style={{ color: 'var(--text-2)', marginBottom: 4 }}>"devices": [</div>
              {encrypted.devices.map((dev, di) => (
                <div key={di} style={{ paddingLeft: 14 }}>
                  <div style={{ color: 'var(--border-strong)' }}>{'{'}</div>
                  <div style={{ paddingLeft: 14 }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <span style={{ color: 'var(--text-2)' }}>"deviceId":</span>
                      <span style={{ color: 'var(--blue)' }}>"{dev.deviceId}",</span>
                    </div>
                    <div style={{ color: 'var(--text-2)', marginTop: 4 }}>"fields": {'{'}</div>
                    {Object.entries(dev.fields).map(([key, { ciphertext, nonce }]) => (
                      <div key={key} style={{ paddingLeft: 14, marginBottom: 6 }}>
                        <span style={{ color: 'var(--text-2)' }}>"{key}":</span>
                        <div style={{ paddingLeft: 14 }}>
                          <div style={{ color: 'var(--border-strong)' }}>{'{'}</div>
                          <div style={{ paddingLeft: 10 }}>
                            <div>
                              <span style={{ color: 'var(--text-3)' }}>"ct": </span>
                              <span style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>
                                "{ciphertext.slice(0, 18)}…",
                              </span>
                            </div>
                            <div>
                              <span style={{ color: 'var(--text-3)' }}>"n": </span>
                              <span style={{ color: 'var(--amber)' }}>"{nonce.slice(0, 14)}…"</span>
                            </div>
                          </div>
                          <div style={{ color: 'var(--border-strong)' }}>{'},'}</div>
                        </div>
                      </div>
                    ))}
                    <div style={{ color: 'var(--text-2)' }}>{'},'}</div>
                  </div>
                  <div style={{ color: 'var(--border-strong)' }}>
                    {di < encrypted.devices.length - 1 ? '},' : '}'}
                  </div>
                </div>
              ))}
              <div style={{ color: 'var(--text-2)' }}>]</div>
            </div>
            <div style={{ color: 'var(--border-strong)' }}>{'}'}</div>
            <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 3 }}>
              <p style={{ color: 'var(--text-3)', fontSize: 10 }}>field names → visible</p>
              <p style={{ color: 'var(--accent)', fontSize: 10 }}>field values → encrypted ✓</p>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ── FormDemo ───────────────────────────────────────────────────────────────────

export default function FormDemo({ config, sessionId }: Props) {
  const [encrypted, setEncrypted] = useState<EncryptedFields | null>(null)
  const aliceId = `alice-form-${sessionId}`
  const bobId   = `bob-form-${sessionId}`

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, flex: 1, minHeight: 0 }}>
      <div className="info-banner">
        <span style={{ color: 'var(--accent)', flexShrink: 0 }}>ℹ</span>
        <span>
          Alice (patient) encrypts a HIPAA intake form for Bob (doctor). Each field gets a unique nonce.
          The <span className="mono" style={{ color: 'var(--text-1)' }}>payload.json</span> shows
          field names in plaintext, values as ciphertext — only Bob's key can decrypt.
        </span>
      </div>
      <div style={{ display: 'flex', gap: 12, flex: 1, minHeight: 0 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <AlicePanel userId={aliceId} recipientId={bobId} config={config} onEncrypted={setEncrypted} />
        </div>
        <div style={{ width: 240, flexShrink: 0 }}>
          <WirePanel encrypted={encrypted} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <BobPanel userId={bobId} senderId={aliceId} config={config} encrypted={encrypted} />
        </div>
      </div>
    </div>
  )
}
