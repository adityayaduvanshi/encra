import { useRef, useState } from 'react'
import { useE2EFile } from '@encra/react'
import type { EncryptedFile } from '@encra/react'
import type { Config } from '../App'
import { StatusBadge } from './StatusBadge'

interface Props {
  config: Config
  sessionId: string
}

function b64(bytes: Uint8Array, len = 24): string {
  let s = ''
  const end = Math.min(bytes.length, len)
  for (let i = 0; i < end; i++) s += String.fromCharCode(bytes[i]!)
  return btoa(s).slice(0, len) + '…'
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

// ── Alice panel ────────────────────────────────────────────────────────────────

interface AliceProps {
  userId: string
  recipientId: string
  config: Config
  onEncrypted: (ef: EncryptedFile) => void
}

function AlicePanel({ userId, recipientId, config, onEncrypted }: AliceProps) {
  const { encryptFile, isReady, error } = useE2EFile({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [file,     setFile]     = useState<File | null>(null)
  const [busy,     setBusy]     = useState(false)
  const [done,     setDone]     = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  async function handleEncrypt() {
    if (!file || !isReady) return
    setBusy(true)
    try {
      const ef = await encryptFile(file, recipientId)
      onEncrypted(ef)
      setDone(true)
    } catch (err) {
      console.error(err)
    } finally {
      setBusy(false)
    }
  }

  function reset() {
    setFile(null)
    setDone(false)
  }

  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-xl">👩</span>
          <div>
            <p className="font-semibold text-slate-100 leading-none">Alice <span className="text-slate-500 font-normal text-xs">sender</span></p>
            <p className="text-xs text-slate-500 font-mono mt-0.5 truncate">{userId}</p>
          </div>
        </div>
        <StatusBadge isReady={isReady} isConnecting={false} error={error} />
      </div>

      <div className="flex-1 flex flex-col items-center justify-center p-6 gap-4">
        {done ? (
          <div className="text-center space-y-3">
            <div className="text-5xl">✅</div>
            <p className="text-emerald-400 font-medium">File encrypted!</p>
            <p className="text-slate-400 text-sm">
              Payload sent to Bob's panel →
            </p>
            <button
              onClick={reset}
              className="text-sm text-slate-400 hover:text-slate-200 underline underline-offset-2"
            >
              Encrypt another file
            </button>
          </div>
        ) : (
          <>
            {/* Drop zone */}
            <div
              onClick={() => inputRef.current?.click()}
              className={`w-full border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
                file
                  ? 'border-emerald-700 bg-emerald-950/30'
                  : 'border-slate-700 hover:border-slate-500'
              }`}
            >
              <input
                ref={inputRef}
                type="file"
                className="hidden"
                onChange={(e) => { setFile(e.target.files?.[0] ?? null) }}
              />
              {file ? (
                <div className="space-y-1">
                  <p className="text-2xl">📄</p>
                  <p className="font-medium text-slate-100">{file.name}</p>
                  <p className="text-xs text-slate-400">{file.type || 'unknown type'} · {fmtBytes(file.size)}</p>
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-3xl">📂</p>
                  <p className="text-slate-400 text-sm">Click to pick a file</p>
                  <p className="text-slate-600 text-xs">Max 50 MB</p>
                </div>
              )}
            </div>

            <button
              onClick={handleEncrypt}
              disabled={!file || !isReady || busy}
              className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium rounded-lg transition-colors text-sm"
            >
              {busy ? 'Encrypting…' : `🔒 Encrypt for Bob`}
            </button>
          </>
        )}

        {error && (
          <p className="text-xs text-red-400 text-center">{error.message}</p>
        )}
      </div>
    </div>
  )
}

// ── Bob panel ──────────────────────────────────────────────────────────────────

interface BobProps {
  userId: string
  senderId: string
  config: Config
  encrypted: EncryptedFile | null
}

function BobPanel({ userId, senderId, config, encrypted }: BobProps) {
  const { decryptFile, isReady, error } = useE2EFile({
    apiKey: config.apiKey, userId, serverUrl: config.serverUrl,
  })
  const [result, setResult] = useState<File | null>(null)
  const [busy,   setBusy]   = useState(false)
  const [decErr, setDecErr] = useState<string | null>(null)

  async function handleDecrypt() {
    if (!encrypted || !isReady) return
    setBusy(true)
    setDecErr(null)
    try {
      const f = await decryptFile(encrypted, senderId)
      setResult(f)
    } catch (err) {
      setDecErr(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  function download() {
    if (!result) return
    const url = URL.createObjectURL(result)
    const a   = document.createElement('a')
    a.href = url; a.download = result.name; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-xl">👨</span>
          <div>
            <p className="font-semibold text-slate-100 leading-none">Bob <span className="text-slate-500 font-normal text-xs">recipient</span></p>
            <p className="text-xs text-slate-500 font-mono mt-0.5 truncate">{userId}</p>
          </div>
        </div>
        <StatusBadge isReady={isReady} isConnecting={false} error={error} />
      </div>

      <div className="flex-1 flex flex-col items-center justify-center p-6 gap-4">
        {result ? (
          <div className="text-center space-y-3">
            <div className="text-5xl">📄</div>
            <p className="text-emerald-400 font-medium">Decrypted successfully!</p>
            <div className="bg-slate-800 rounded-lg px-4 py-3 text-sm space-y-1">
              <p className="text-slate-200 font-medium">{result.name}</p>
              <p className="text-slate-400 text-xs">{result.type || 'unknown type'} · {fmtBytes(result.size)}</p>
            </div>
            <button
              onClick={download}
              className="px-6 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              ⬇ Download
            </button>
            <button
              onClick={() => setResult(null)}
              className="block text-xs text-slate-500 hover:text-slate-300 mx-auto"
            >
              Reset
            </button>
          </div>
        ) : (
          <div className="text-center space-y-4 w-full">
            {!encrypted ? (
              <div className="space-y-2">
                <div className="text-4xl opacity-30">📭</div>
                <p className="text-slate-600 text-sm">Waiting for Alice to encrypt a file…</p>
              </div>
            ) : (
              <>
                <div className="bg-slate-800 rounded-lg px-4 py-3 text-sm space-y-1 text-left">
                  <p className="text-slate-400 text-xs uppercase tracking-wide mb-2">Incoming encrypted file</p>
                  <p className="text-slate-200 font-medium">{encrypted.name}</p>
                  <p className="text-slate-400 text-xs">{encrypted.mimeType} · {fmtBytes(encrypted.size)}</p>
                  <p className="text-slate-500 text-xs mt-1">{encrypted.devices.length} device envelope(s)</p>
                </div>
                <button
                  onClick={handleDecrypt}
                  disabled={!isReady || busy}
                  className="w-full py-2.5 bg-purple-700 hover:bg-purple-600 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium rounded-lg transition-colors text-sm"
                >
                  {busy ? 'Decrypting…' : '🔓 Decrypt File'}
                </button>
              </>
            )}
            {decErr && (
              <p className="text-xs text-red-400">{decErr}</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Wire / payload panel ───────────────────────────────────────────────────────

function WirePanel({ encrypted }: { encrypted: EncryptedFile | null }) {
  return (
    <div className="flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden h-full">
      <div className="px-4 py-3 border-b border-slate-800 shrink-0">
        <p className="text-sm font-semibold text-slate-300">🔌 Wire</p>
        <p className="text-xs text-slate-500 mt-0.5">EncryptedFile payload</p>
      </div>
      <div className="flex-1 overflow-y-auto p-3 min-h-0">
        {!encrypted ? (
          <p className="text-center text-slate-600 text-xs pt-8">
            Encrypt a file to see the payload
          </p>
        ) : (
          <div className="text-xs font-mono space-y-1 text-slate-400">
            <p><span className="text-slate-500">name     </span><span className="text-slate-200">{encrypted.name}</span></p>
            <p><span className="text-slate-500">mimeType </span><span className="text-slate-200">{encrypted.mimeType}</span></p>
            <p><span className="text-slate-500">size     </span><span className="text-slate-200">{fmtBytes(encrypted.size)}</span></p>
            <p className="mt-2 text-slate-500 uppercase tracking-wide text-[10px]">devices ({encrypted.devices.length})</p>
            {encrypted.devices.map((d, i) => (
              <div key={i} className="bg-slate-800 rounded-lg p-2 space-y-1 mt-1">
                <p><span className="text-slate-500">deviceId  </span><span className="text-blue-400">{d.deviceId}</span></p>
                <p><span className="text-slate-500">ciphertext</span></p>
                <p className="text-emerald-400 break-all pl-2">{b64(d.ciphertext)}</p>
                <p><span className="text-slate-500">nonce     </span><span className="text-amber-400">{b64(d.nonce, 16)}</span></p>
              </div>
            ))}
            <p className="text-slate-600 pt-2 text-[10px] leading-relaxed">
              The server stores only these bytes — name, mime type, and ciphertext.
              Without the private key it is computationally infeasible to recover the plaintext.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// ── FileDemo ──────────────────────────────────────────────────────────────────

export default function FileDemo({ config, sessionId }: Props) {
  const [encrypted, setEncrypted] = useState<EncryptedFile | null>(null)

  const aliceId = `alice-file-${sessionId}`
  const bobId   = `bob-file-${sessionId}`

  return (
    <div className="space-y-4 h-full">
      <div className="flex gap-2 text-xs text-slate-400 bg-slate-900 rounded-lg px-4 py-3 border border-slate-800">
        <span className="text-blue-400 shrink-0 mt-px">ℹ</span>
        <span>
          Alice encrypts a file using her private key and Bob's public key (X25519 + XSalsa20-Poly1305).
          The <strong className="text-slate-300">Wire</strong> panel shows what gets transmitted —
          an <code className="text-emerald-400">EncryptedFile</code> with one envelope per recipient device.
          Bob's key decrypts only the envelope addressed to his device.
        </span>
      </div>

      <div className="grid grid-cols-[1fr_240px_1fr] gap-4" style={{ height: 'calc(100vh - 260px)', minHeight: '400px' }}>
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
