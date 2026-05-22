import { describe, it, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import React from 'react'
import { E2EChatProvider, useE2EChatConfig } from '../src/E2EChatProvider.js'

describe('E2EChatProvider', () => {
  it('provides apiKey and serverUrl to children', () => {
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <E2EChatProvider apiKey="test-api-key" serverUrl="https://api.example.com">
        {children}
      </E2EChatProvider>
    )

    const { result } = renderHook(() => useE2EChatConfig(), { wrapper })
    expect(result.current.apiKey).toBe('test-api-key')
    expect(result.current.serverUrl).toBe('https://api.example.com')
  })

  it('throws when used outside E2EChatProvider', () => {
    expect(() => renderHook(() => useE2EChatConfig())).toThrow(
      'useE2EChatConfig must be used inside <E2EChatProvider>.'
    )
  })
})
