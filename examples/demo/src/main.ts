import { EncraClient } from '@encra/client'
import type { Message, StoredMessageRecord } from '@encra/client'

/** Small page size so pagination is visible with only a handful of messages. */
const PAGE_SIZE = 5

/** POST one at-rest record into the "developer's DB" (the mock server's app DB). */
async function saveToAppDb(userId: string, record: StoredMessageRecord): Promise<void> {
  await fetch('/app/messages', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ userId, record }),
  })
}

/** Load one page of at-rest records for a conversation, newest-first. */
async function loadAppDbPage(
  userId: string, conversationId: string, before: number | null,
): Promise<{ records: StoredMessageRecord[]; nextBefore: number | null }> {
  const p = new URLSearchParams({ userId, conversationId, limit: String(PAGE_SIZE) })
  if (before !== null) p.set('before', String(before))
  const res = await fetch(`/app/messages?${p.toString()}`)
  return res.json() as Promise<{ records: StoredMessageRecord[]; nextBefore: number | null }>
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
  const olderBtn  = section.querySelector<HTMLButtonElement>('.older')!

  let oldestLoaded: number | null = null  // for "Load older" pagination
  let loadedOnce = false

  const client = new EncraClient({
    apiKey:    'demo-key',
    userId,
    // Same origin as the page — the Vite dev server also hosts the mock relay.
    serverUrl: window.location.origin,
  })

  function makeBubble(msg: Message): HTMLDivElement {
    const el = document.createElement('div')
    el.className = `msg ${msg.from === userId ? 'me' : 'them'}`
    el.innerHTML = `<div>${escapeHtml(msg.text)}</div>` +
      `<div class="t">${msg.from === userId ? 'you' : msg.from} · ${new Date(msg.timestamp).toLocaleTimeString()}</div>`
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

  /** Load this conversation's history from the developer DB (newest page) and render it. */
  async function loadFromDb(): Promise<void> {
    log.innerHTML = ''
    oldestLoaded = null
    const { records, nextBefore } = await loadAppDbPage(userId, peerId, null)
    // Records come newest-first; render oldest-first. Skip any record we can't
    // decrypt (e.g. one written under a storage key that was since reset).
    for (const rec of [...records].reverse()) {
      try { addBubble(await client.decryptFromStorage(rec)) }
      catch (e) { console.warn('[decrypt-skip]', userId, rec.id.slice(0, 6), (e as Error)?.message) }
    }
    oldestLoaded = records.length ? records[records.length - 1]!.timestamp : null
    olderBtn.hidden = nextBefore === null
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

  // "Load older" — fetch the previous page and prepend it (decrypt-on-demand).
  olderBtn.addEventListener('click', async () => {
    const { records, nextBefore } = await loadAppDbPage(userId, peerId, oldestLoaded)
    for (const rec of records) {                    // newest-first → prepend keeps order
      try {
        log.insertBefore(makeBubble(await client.decryptFromStorage(rec)), log.firstChild)
      } catch { /* skip undecryptable */ }
    }
    if (records.length) oldestLoaded = records[records.length - 1]!.timestamp
    olderBtn.hidden = nextBefore === null
  })

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
