// ── Global debug log store ──────────────────────────────────────────────────
// Module-level singleton; no React required.  Components call emitLog(); the
// LogsDialog subscribes with onLog().

export type LogCategory = 'SYSTEM' | 'KEY' | 'TRANSPORT' | 'RATCHET' | 'CRYPTO' | 'ERROR'

export interface LogField {
  label: string
  value: string
  mono?: boolean   // default true (monospace value)
}

export interface LogEntry {
  id:       number
  ts:       number
  category: LogCategory
  actor:    string   // 'Alice' | 'Bob' | 'System'
  title:    string
  fields?:  LogField[]
}

let _id = 0
const _listeners = new Set<(e: LogEntry) => void>()

export function emitLog(entry: Omit<LogEntry, 'id' | 'ts'>): void {
  const full: LogEntry = { ...entry, id: _id++, ts: Date.now() }
  _listeners.forEach(fn => fn(full))
}

/** Returns an unsubscribe function. */
export function onLog(fn: (e: LogEntry) => void): () => void {
  _listeners.add(fn)
  return () => void _listeners.delete(fn)
}
