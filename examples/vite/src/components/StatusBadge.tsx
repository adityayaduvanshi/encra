interface Props {
  isReady: boolean
  isConnecting: boolean
  error: Error | null
}

export function StatusDot({ isReady, isConnecting, error }: Props) {
  if (error)
    return (
      <div className="flex items-center gap-1.5">
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--red)', flexShrink: 0 }} />
        <span className="mono" style={{ fontSize: 10, color: 'var(--red)' }}>error</span>
      </div>
    )

  if (isConnecting)
    return (
      <div className="flex items-center gap-1.5">
        <div
          style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--amber)', flexShrink: 0 }}
          className="animate-pulse"
        />
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)' }}>connecting</span>
      </div>
    )

  if (isReady)
    return (
      <div className="flex items-center gap-1.5">
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)', flexShrink: 0 }} />
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)' }}>ready</span>
      </div>
    )

  return (
    <div className="flex items-center gap-1.5">
      <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--border-strong)', flexShrink: 0 }} />
      <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)' }}>idle</span>
    </div>
  )
}

// Alias so any stale import of the old name keeps working
export { StatusDot as StatusBadge }
