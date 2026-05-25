import { useRef, useState, useEffect } from 'react'
import { useE2EFile } from '@encra/react'
import type { EncryptedFile } from '@encra/react'
import type { Config } from '../App'
import { StatusDot } from './StatusBadge'
import { emitLog } from '../lib/logger'

interface Props { config: Config; sessionId: string }

function fmt(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1048576).toFixed(2)} MB`
}

function b64preview(bytes: Uint8Array, len = 28): string {
  let s = ''
  const end = Math.min(bytes.length, len)
  for (let i = 0; i < end; i++) s += String.fromCharCode(bytes[i]!)
  return btoa(s).slice(0, len)
}

// ── Alice panel ────────────────────────────────────────────────────────────────

function AlicePanel({
  userId, recipientId, config, onEncrypted,
}: {
  userId: string; recipientId: string; config: Config; onEncrypted: (ef: EncryptedFile) => void
}) {
  const { encryptFile, isReady, error } = useE2EFile({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [file,   setFile]   = useState<File | null>(null)
  const [busy,   setBusy]   = useState(false)
  const [done,   setDone]   = useState(false)
  const [encErr, setEncErr] = useState<string | null>(null)
  const inputRef  = useRef<HTMLInputElement>(null)
  const didLogRef = useRef(false)

  useEffect(() => {
    if (isReady && !didLogRef.current) {
      didLogRef.current = true
      emitLog({
        category: 'KEY', actor: 'Alice',
        title: 'X25519 key pair registered (file hook)',
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

  async function handleEncrypt() {
    if (!file || !isReady) return
    setBusy(true); setEncErr(null)

    emitLog({
      category: 'KEY', actor: 'Alice',
      title: 'Fetching recipient device public keys',
      fields: [
        { label: 'for',      value: recipientId         },
        { label: 'endpoint', value: 'GET /v1/keys/:userId' },
      ],
    })
    emitLog({
      category: 'CRYPTO', actor: 'Alice',
      title: 'Starting file encryption',
      fields: [
        { label: 'file',      value: file.name                                  },
        { label: 'size',      value: fmt(file.size)                             },
        { label: 'mime',      value: file.type || 'unknown'                     },
        { label: 'algorithm', value: 'X25519 ECDH → shared secret → XSalsa20-Poly1305' },
        { label: 'nonce',     value: 'random 24 bytes (libsodium randombytes)'  },
      ],
    })

    try {
      const ef = await encryptFile(file, recipientId)
      emitLog({
        category: 'CRYPTO', actor: 'Alice',
        title: `File encrypted for ${ef.devices.length} device(s)`,
        fields: [
          { label: 'devices',    value: ef.devices.map(d => d.deviceId).join(', ') },
          { label: 'ciphertext', value: b64preview(ef.devices[0]?.ciphertext ?? new Uint8Array(), 28) + '…' },
          { label: 'nonce',      value: b64preview(ef.devices[0]?.nonce      ?? new Uint8Array(), 18) + '…' },
          { label: 'mac',        value: 'Poly1305 authenticator appended to ciphertext' },
          { label: 'plaintext',  value: '(zero-knowledge — only ciphertext leaves device)' },
        ],
      })
      onEncrypted(ef); setDone(true)
    } catch (e) {
      emitLog({
        category: 'ERROR', actor: 'Alice',
        title: 'File encryption failed',
        fields: [{ label: 'error', value: e instanceof Error ? e.message : String(e) }],
      })
      setEncErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  if (done) return (
    <div className="panel flex flex-col items-center justify-center" style={{ height: '100%', gap: 12, padding: 24 }}>
      <div style={{
        width: 48, height: 48, borderRadius: 12,
        background: 'var(--accent-dim)', border: '1px solid var(--accent-border)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22,
      }}>
        ✓
      </div>
      <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>File encrypted</p>
      <p style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center' }}>
        Payload sent to Bob's panel →
      </p>
      <button
        className="btn btn-ghost"
        style={{ marginTop: 4 }}
        onClick={() => { setFile(null); setDone(false) }}
      >
        Encrypt another
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
            <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>sender</p>
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={false} error={error} />
      </div>

      <div className="flex-1 flex flex-col justify-center" style={{ padding: 20, gap: 12 }}>
        {/* Drop zone */}
        <div
          className={`drop-zone${file ? ' has-file' : ''}`}
          onClick={() => inputRef.current?.click()}
        >
          <input
            ref={inputRef} type="file" className="hidden"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          {file ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
              <div style={{
                width: 36, height: 36, borderRadius: 8,
                background: 'var(--accent-dim)', border: '1px solid var(--accent-border)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
              }}>
                📄
              </div>
              <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-1)' }}>{file.name}</p>
              <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)' }}>
                {file.type || 'unknown'} · {fmt(file.size)}
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
              <p style={{ fontSize: 22, opacity: 0.4 }}>⊕</p>
              <p style={{ fontSize: 13, color: 'var(--text-2)' }}>Click to select a file</p>
              <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)' }}>max 50 MB</p>
            </div>
          )}
        </div>

        {encErr && (
          <p className="mono" style={{ fontSize: 11, color: 'var(--red)' }}>{encErr}</p>
        )}

        <button
          className="btn btn-accent"
          style={{ width: '100%' }}
          onClick={handleEncrypt}
          disabled={!file || !isReady || busy}
        >
          {busy ? 'Encrypting…' : '🔒 Encrypt for Bob'}
        </button>
      </div>
    </div>
  )
}

// ── Bob panel ──────────────────────────────────────────────────────────────────

function BobPanel({
  userId, senderId, config, encrypted,
}: {
  userId: string; senderId: string; config: Config; encrypted: EncryptedFile | null
}) {
  const { decryptFile, isReady, error } = useE2EFile({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [result, setResult] = useState<File | null>(null)
  const [busy,   setBusy]   = useState(false)
  const [decErr, setDecErr] = useState<string | null>(null)
  const didLogRef = useRef(false)

  useEffect(() => {
    if (isReady && !didLogRef.current) {
      didLogRef.current = true
      emitLog({
        category: 'KEY', actor: 'Bob',
        title: 'X25519 key pair registered (file hook)',
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

    emitLog({
      category: 'KEY', actor: 'Bob',
      title: 'Locating device envelope in payload',
      fields: [
        { label: 'envelopes', value: encrypted.devices.length.toString()     },
        { label: 'action',    value: 'finding envelope addressed to this device' },
      ],
    })
    emitLog({
      category: 'CRYPTO', actor: 'Bob',
      title: 'XSalsa20-Poly1305 file decrypt',
      fields: [
        { label: 'file',      value: encrypted.name                                   },
        { label: 'algorithm', value: 'X25519 ECDH → shared secret → XSalsa20-Poly1305 decrypt' },
        { label: 'nonce',     value: b64preview(encrypted.devices[0]?.nonce ?? new Uint8Array(), 18) + '…' },
        { label: 'mac check', value: 'Poly1305 MAC verified before decryption'        },
      ],
    })

    try {
      const result = await decryptFile(encrypted, senderId)
      emitLog({
        category: 'CRYPTO', actor: 'Bob',
        title: 'File decrypted successfully',
        fields: [
          { label: 'file',      value: result.name     },
          { label: 'size',      value: fmt(result.size) },
          { label: 'integrity', value: '✓ Poly1305 MAC verified'          },
          { label: 'key source','value': `X25519(Bob.priv, Alice.pub)`    },
        ],
      })
      setResult(result)
    } catch (e) {
      emitLog({
        category: 'ERROR', actor: 'Bob',
        title: 'File decryption failed',
        fields: [{ label: 'error', value: e instanceof Error ? e.message : String(e) }],
      })
      setDecErr(e instanceof Error ? e.message : String(e))
    } finally { setBusy(false) }
  }

  function download() {
    if (!result) return
    const url = URL.createObjectURL(result)
    const a = document.createElement('a')
    a.href = url; a.download = result.name; a.click()
    URL.revokeObjectURL(url)
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
            <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>recipient</p>
          </div>
        </div>
        <StatusDot isReady={isReady} isConnecting={false} error={error} />
      </div>

      <div className="flex-1 flex flex-col items-center justify-center" style={{ padding: 20, gap: 12 }}>
        {result ? (
          <>
            <div style={{
              width: 48, height: 48, borderRadius: 12,
              background: 'var(--purple-dim)', border: '1px solid rgba(168,85,247,0.25)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22,
            }}>📄</div>
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--purple)' }}>Decrypted</p>
            <div style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              borderRadius: 8, padding: '10px 14px', textAlign: 'center', width: '100%',
            }}>
              <p style={{ fontSize: 13, fontWeight: 500 }}>{result.name}</p>
              <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 3 }}>
                {result.type || 'unknown'} · {fmt(result.size)}
              </p>
            </div>
            <button className="btn btn-purple" style={{ width: '100%' }} onClick={download}>
              ⬇ Download
            </button>
            <button
              className="mono"
              style={{ fontSize: 10, color: 'var(--text-3)', background: 'none', border: 'none', cursor: 'pointer' }}
              onClick={() => setResult(null)}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-2)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
            >
              reset
            </button>
          </>
        ) : !encrypted ? (
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
              <p className="mono" style={{ fontSize: 9, color: 'var(--text-3)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Incoming file
              </p>
              <p style={{ fontSize: 13, fontWeight: 500 }}>{encrypted.name}</p>
              <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>
                {encrypted.mimeType} · {fmt(encrypted.size)}
              </p>
              <p className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>
                {encrypted.devices.length} device envelope(s)
              </p>
            </div>
            <button
              className="btn btn-purple" style={{ width: '100%' }}
              onClick={handleDecrypt}
              disabled={!isReady || busy}
            >
              {busy ? 'Decrypting…' : '🔓 Decrypt file'}
            </button>
            {decErr && <p className="mono" style={{ fontSize: 11, color: 'var(--red)' }}>{decErr}</p>}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Wire panel ─────────────────────────────────────────────────────────────────

function WirePanel({ encrypted }: { encrypted: EncryptedFile | null }) {
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
            encrypt a file to see payload
          </p>
        ) : (
          <>
            <div style={{ color: 'var(--border-strong)' }}>{'{'}</div>
            <div style={{ paddingLeft: 14 }}>
              <JsonLine k="name"     v={`"${encrypted.name}"`}     vc="var(--amber)" />
              <JsonLine k="mimeType" v={`"${encrypted.mimeType}"`} vc="var(--amber)" />
              <JsonLine k="size"     v={fmt(encrypted.size)}       vc="var(--blue)"  />
              <div style={{ marginTop: 6, color: 'var(--text-2)' }}>"devices": [</div>
              {encrypted.devices.map((d, i) => (
                <div key={i} style={{ paddingLeft: 14 }}>
                  <div style={{ color: 'var(--border-strong)' }}>{'{'}</div>
                  <div style={{ paddingLeft: 14 }}>
                    <JsonLine k="deviceId"   v={`"${d.deviceId}"`}             vc="var(--blue)"   />
                    <JsonLine k="ciphertext" v={`"${b64preview(d.ciphertext)}…"` } vc="var(--accent)" />
                    <JsonLine k="nonce"      v={`"${b64preview(d.nonce, 16)}…"`}  vc="var(--amber)"  />
                  </div>
                  <div style={{ color: 'var(--border-strong)' }}>{i < encrypted.devices.length - 1 ? '},' : '}'}</div>
                </div>
              ))}
              <div style={{ color: 'var(--text-2)' }}>]</div>
            </div>
            <div style={{ color: 'var(--border-strong)' }}>{'}'}</div>
            <p style={{ marginTop: 14, color: 'var(--text-3)', fontSize: 10, lineHeight: 1.6 }}>
              ↑ only ciphertext is stored server-side.{'\n'}
              private key never leaves the device.
            </p>
          </>
        )}
      </div>
    </div>
  )
}

function JsonLine({ k, v, vc }: { k: string; v: string; vc: string }) {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      <span style={{ color: 'var(--text-2)' }}>"{k}":</span>
      <span style={{ color: vc, wordBreak: 'break-all' }}>{v},</span>
    </div>
  )
}

// ── FileDemo ───────────────────────────────────────────────────────────────────

export default function FileDemo({ config, sessionId }: Props) {
  const [encrypted, setEncrypted] = useState<EncryptedFile | null>(null)
  const aliceId = `alice-file-${sessionId}`
  const bobId   = `bob-file-${sessionId}`

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, flex: 1, minHeight: 0 }}>
      <div className="info-banner">
        <span style={{ color: 'var(--accent)', flexShrink: 0 }}>ℹ</span>
        <span>
          Alice encrypts using X25519 + XSalsa20-Poly1305. One ciphertext per recipient device.
          The <span className="mono" style={{ color: 'var(--text-1)' }}>payload.json</span> panel shows
          exactly what gets stored — ciphertext, never plaintext.
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
