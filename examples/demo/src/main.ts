import { EncraClient } from '@encra/client'
import type { Message, StoredMessageRecord } from '@encra/client'

/** POST one at-rest record into the "developer's DB" (the mock server's app DB). */
async function saveToAppDb(userId: string, record: StoredMessageRecord): Promise<void> {
  const res = await fetch('/app/messages', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ userId, record }),
  })
  if (!res.ok) throw new Error(`app DB save failed: ${res.status}`)  // surface, don't lose silently
}

/**
 * Load the whole conversation (oldest-first) from the developer DB. The GET
 * endpoint also supports `?before=&limit=` for real pagination (see README); the
 * demo loads everything so nothing ever looks missing.
 */
async function loadConversation(userId: string, conversationId: string): Promise<StoredMessageRecord[]> {
  const p = new URLSearchParams({ userId, conversationId, limit: '200' })
  const res = await fetch(`/app/messages?${p.toString()}`)
  const data = (await res.json()) as { records: StoredMessageRecord[] }
  return [...data.records].reverse()   // server returns newest-first
}

/**
 * Wires one chat panel (`<section data-user=... data-peer=...>`) to its own
 * EncraClient. Two panels run side by side in the page, each a separate user,
 * talking to each other through the in-memory relay mounted by the Vite plugin.
 */
function mountPanel(section: HTMLElement): { client: EncraClient; userId: string } {
  const userId = section.dataset.user!
  const peerId = section.dataset.peer!

  const dot      = section.querySelector<HTMLSpanElement>('.dot')!
  const device   = section.querySelector<HTMLSpanElement>('.device')!
  const log       = section.querySelector<HTMLDivElement>('.log')!
  const form      = section.querySelector<HTMLFormElement>('.compose')!
  const input     = section.querySelector<HTMLInputElement>('input')!
  // The Send button lives in the compose form; `section.querySelector('button')`
  // would wrongly match the storebar's "Reload from DB" button (it comes first in
  // the DOM), leaving the real Send button disabled.
  const button    = form.querySelector<HTMLButtonElement>('button')!
  const storedEl  = section.querySelector<HTMLSpanElement>('.stored')!
  const rehydrate = section.querySelector<HTMLButtonElement>('.rehydrate')!
  const offlineBtn = section.querySelector<HTMLButtonElement>('.offline')!

  let loadedOnce = false
  let offline = false
  const bubbles = new Map<string, HTMLDivElement>()   // id → sent bubble, for status updates

  const client = new EncraClient({
    apiKey:    'demo-key',
    userId,
    // Same origin as the page — the Vite dev server also hosts the mock relay.
    serverUrl: window.location.origin,
  })

  const STATUS_GLYPH: Record<string, string> = { queued: '⏳', sending: '…', sent: '✓', failed: '✗' }
  function statusHtml(msg: Message): string {
    if (msg.from !== userId || !msg.status) return ''
    return ` <span class="st ${msg.status}">${STATUS_GLYPH[msg.status] ?? ''}</span>`
  }
  function makeBubble(msg: Message): HTMLDivElement {
    const el = document.createElement('div')
    el.className = `msg ${msg.from === userId ? 'me' : 'them'}`
    el.innerHTML = `<div>${escapeHtml(msg.text)}</div>` +
      `<div class="t">${msg.from === userId ? 'you' : msg.from} · ${new Date(msg.timestamp).toLocaleTimeString()}${statusHtml(msg)}</div>`
    if (msg.from === userId) bubbles.set(msg.id, el)   // track sent bubbles for status updates
    return el
  }
  function addBubble(msg: Message): void {
    log.appendChild(makeBubble(msg))
    log.scrollTop = log.scrollHeight
  }

  /** Update the 💾 badge from the developer DB (reflects persisted history). */
  async function refreshStored(): Promise<void> {
    try {
      const r = await fetch(
        `/app/messages?userId=${encodeURIComponent(userId)}&conversationId=${encodeURIComponent(peerId)}&limit=200`,
      ).then((x) => x.json() as Promise<{ records: unknown[] }>)
      storedEl.textContent = String(r.records.length)
    } catch { /* ignore */ }
  }

  /** Load the whole conversation from the developer DB and render it. */
  async function loadFromDb(): Promise<void> {
    log.innerHTML = ''
    const records = await loadConversation(userId, peerId)   // oldest-first
    for (const rec of records) {
      // Skip any record we can't decrypt (e.g. one written under a storage key
      // that was since reset) rather than aborting the whole render.
      try {
        const msg = await client.decryptFromStorage(rec)
        if (msg.from === userId) msg.status = 'sent'   // persisted history was delivered
        addBubble(msg)
      } catch (e) { console.warn('[decrypt-skip]', userId, rec.id.slice(0, 6), (e as Error)?.message) }
    }
    await refreshStored()
  }

  client.on('ready', () => {
    dot.classList.add('on')
    input.disabled = false
    button.disabled = false
    device.textContent = client.deviceId ?? '?'
    input.focus()
    // Restore history from the developer DB on first connect — the realistic
    // "open the app" flow, so a page reload keeps the conversation on screen.
    if (!loadedOnce) { loadedOnce = true; void loadFromDb() }
  })
  client.on('disconnected', () => dot.classList.remove('on'))
  client.on('error', (err) => console.warn(`[${userId}]`, err.message))

  // Update a sent bubble's status glyph (⏳ queued · … sending · ✓ sent · ✗ failed).
  client.on('status', ({ id, status }) => {
    const st = bubbles.get(id)?.querySelector('.st')
    if (st) { st.className = `st ${status}`; st.textContent = STATUS_GLYPH[status] ?? '' }
  })

  // Offline toggle — demonstrates the outbox: go offline, type (messages queue
  // with ⏳), go online, watch them flush (✓).
  offlineBtn.addEventListener('click', () => {
    offline = !offline
    if (offline) { client.goOffline(); offlineBtn.textContent = 'Go online' }
    else { client.goOnline(); offlineBtn.textContent = 'Go offline' }
  })

  // Every message (sent echo + received) is shown AND persisted to the app DB as
  // an at-rest record — ciphertext in the developer's database, decryptable later.
  client.on('message', async (msg) => {
    addBubble(msg)
    try {
      const record = await client.encryptForStorage(msg)
      await saveToAppDb(userId, record)
      await refreshStored()
    } catch (err) {
      console.warn(`[${userId}] store failed:`, err)
    }
  })

  // "Reload from DB" — clear the pane and re-render purely from the encrypted
  // records in the developer's DB (same path used automatically on open).
  rehydrate.addEventListener('click', () => { void loadFromDb() })

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    const text = input.value.trim()
    if (!text) return
    input.value = ''
    try {
      await client.sendMessage(peerId, text)
    } catch (err) {
      console.error(`[${userId}] send failed:`, err)
    }
  })

  void client.connect()
  return { client, userId }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!
  ))
}

const panels = [...document.querySelectorAll<HTMLElement>('.panel')].map(mountPanel)
const alice  = panels.find((p) => p.userId === 'alice')!

// ── Safety number (MITM check) ──────────────────────────────────────────────
document.getElementById('safety')!.addEventListener('click', async () => {
  const out = document.getElementById('sn-out')!
  out.textContent = 'computing…'
  const a = await alice.client.getSafetyNumber('bob')
  const b = await panels.find((p) => p.userId === 'bob')!.client.getSafetyNumber('alice')
  if (!a || !b) { out.textContent = 'not ready — send a message first so both sides have prekeys'; return }
  out.innerHTML = a === b
    ? `<span class="match">✓ match</span> &nbsp;${a}`
    : `✗ MISMATCH — Alice: ${a} · Bob: ${b}`
})

// ── Reset: wipe this origin's IndexedDB and reload for a clean session ───────
document.getElementById('reset')!.addEventListener('click', async () => {
  panels.forEach((p) => p.client.disconnect())
  try { await fetch('/app/reset', { method: 'POST' }) } catch { /* ignore */ }
  const req = indexedDB.deleteDatabase('encra-v1')
  req.onsuccess = req.onerror = req.onblocked = () => window.location.reload()
})
