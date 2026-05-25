interface Props {
  isReady: boolean
  isConnecting: boolean
  error: Error | null
}

export function StatusBadge({ isReady, isConnecting, error }: Props) {
  if (error)
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-red-950 text-red-400 border border-red-900">
        <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
        Error
      </span>
    )
  if (isConnecting)
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-amber-950 text-amber-400 border border-amber-900">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
        Connecting…
      </span>
    )
  if (isReady)
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-900">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        Ready
      </span>
    )
  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
      Idle
    </span>
  )
}
