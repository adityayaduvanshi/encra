/**
 * The plaintext payload of a chat message — what gets encrypted as the Double
 * Ratchet body.
 *
 * Carrying the message id and the conversation peer INSIDE the ciphertext (not
 * as plaintext wire fields) keeps them end-to-end authenticated and hidden from
 * the relay, and lets every delivered copy agree on:
 *   - a stable `id` (so all devices dedupe the same message and can attach
 *     receipts to it), and
 *   - the conversation it belongs to (`to`), so the sender's own synced devices
 *     place a message in the right thread even though they received it "from"
 *     the sender, not the recipient.
 */
export interface MessageEnvelope {
  /** Envelope format version. */
  v: 1
  /** Stable, sender-generated message id — identical across all delivered copies. */
  id: string
  /** Recipient userId of the message (the conversation's peer). */
  to: string
  /** The message text. */
  text: string
  /** Sender's send time (ms epoch) — the authoritative timestamp for ordering. */
  ts: number
}

/** The decoded fields of a message payload; `id`/`to`/`ts` are null for legacy raw text. */
export interface DecodedMessage {
  id:   string | null
  to:   string | null
  text: string
  ts:   number | null
}

/**
 * Encode a chat message into the string that gets encrypted as the ratchet body.
 *
 * @example
 * const body = packMessagePayload({ id, to: 'bob', text: 'hi', ts: Date.now() })
 * const enc  = await ratchet.encrypt(body)
 */
export function packMessagePayload(fields: Omit<MessageEnvelope, 'v'>): string {
  const env: MessageEnvelope = { v: 1, ...fields }
  return JSON.stringify(env)
}

/**
 * Decode a decrypted ratchet body back into message fields.
 *
 * Tolerant of legacy senders: anything that is not a well-formed v1 envelope is
 * treated as raw message text, with `id`/`to`/`ts` returned as null so the
 * caller can backfill (generate an id, use the receive time, etc.).
 *
 * @example
 * const { id, to, text, ts } = unpackMessagePayload(await ratchet.decrypt(msg))
 */
export function unpackMessagePayload(raw: string): DecodedMessage {
  try {
    const o = JSON.parse(raw) as Partial<MessageEnvelope>
    if (
      o && o.v === 1 &&
      typeof o.id === 'string' &&
      typeof o.to === 'string' &&
      typeof o.text === 'string' &&
      typeof o.ts === 'number'
    ) {
      return { id: o.id, to: o.to, text: o.text, ts: o.ts }
    }
  } catch { /* not JSON / not our envelope — treat as legacy raw text */ }
  return { id: null, to: null, text: raw, ts: null }
}
