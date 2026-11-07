import { describe, it, expect } from 'vitest'
import { packMessagePayload, unpackMessagePayload } from '../src/message.js'

describe('message envelope', () => {
  it('round-trips id, to, text, and ts', () => {
    const packed = packMessagePayload({ id: 'm1', to: 'bob', text: 'hello 🔐', ts: 1700000000000 })
    const out = unpackMessagePayload(packed)
    expect(out).toEqual({ id: 'm1', to: 'bob', text: 'hello 🔐', ts: 1700000000000 })
  })

  it('treats legacy raw text as text with null metadata', () => {
    const out = unpackMessagePayload('just a plain message')
    expect(out).toEqual({ id: null, to: null, text: 'just a plain message', ts: null })
  })

  it('treats non-envelope JSON as raw text (no false envelope match)', () => {
    const raw = JSON.stringify({ hello: 'world' })
    const out = unpackMessagePayload(raw)
    expect(out.id).toBeNull()
    expect(out.text).toBe(raw)
  })

  it('rejects an envelope with a wrong-typed field', () => {
    const bad = JSON.stringify({ v: 1, id: 1, to: 'bob', text: 'x', ts: 0 }) // id not a string
    const out = unpackMessagePayload(bad)
    expect(out.id).toBeNull()
    expect(out.text).toBe(bad)
  })
})
