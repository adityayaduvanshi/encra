import React, { createContext, useContext } from 'react'

export interface E2EChatConfig {
  apiKey: string
  serverUrl: string
}

const E2EChatContext = createContext<E2EChatConfig | null>(null)

/**
 * Provides shared `apiKey` and `serverUrl` config to any `useE2EChat` call in the subtree.
 * Wrap your app (or chat feature) with this provider to avoid passing config on every hook call.
 *
 * @example
 * <E2EChatProvider apiKey="e2e_live_xxx" serverUrl="https://api.example.com">
 *   <ChatView />
 * </E2EChatProvider>
 */
export function E2EChatProvider({
  apiKey,
  serverUrl,
  children,
}: E2EChatConfig & { children: React.ReactNode }): React.ReactElement {
  return <E2EChatContext.Provider value={{ apiKey, serverUrl }}>{children}</E2EChatContext.Provider>
}

/**
 * Returns the nearest `E2EChatProvider` config. Throws if used outside the provider.
 */
export function useE2EChatConfig(): E2EChatConfig {
  const ctx = useContext(E2EChatContext)
  if (!ctx) throw new Error('useE2EChatConfig must be used inside <E2EChatProvider>.')
  return ctx
}
