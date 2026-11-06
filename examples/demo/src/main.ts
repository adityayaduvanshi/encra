import { EncraClient } from '@encra/client'
import type { Message } from '@encra/client'

/**
 * Wires one chat panel (`<section data-user=... data-peer=...>`) to its own
 * EncraClient. Two panels run side by side in the page, each a separate user,
 * talking to each other through the in-memory relay mounted by the Vite plugin.
 */
function mountPanel(section: HTMLElement): { client: EncraClient; userId: string } {
  const userId = section.dataset.user!
  const peerId = section.dataset.peer!

  const dot    = section.querySelector<HTMLSpanElement>('.dot')!
  const device = section.querySelector<HTMLSpanElement>('.device')!
  const log     = section.querySelector<HTMLDivElement>('.log')!
  const form    = section.querySelector<HTMLFormElement>('.compose')!
  const input   = section.querySelector<HTMLInputElement>('input')!
  const button  = section.querySelector<HTMLButtonElement>('button')!

  const client = new EncraClient({
    apiKey:    'demo-key',
    userId,
    // Same origin as the page — the Vite dev server also hosts the mock relay.
    serverUrl: window.location.origin,
  })

  function addBubble(msg: Message): void {
    const el = document.createElement('div')
    el.className = `msg ${msg.from === userId ? 'me' : 'them'}`
    el.innerHTML = `<div>${escapeHtml(msg.text)}</div>` +
      `<div class="t">${msg.from === userId ? 'you' : msg.from} · ${new Date(msg.timestamp).toLocaleTimeString()}</div>`
    log.appendChild(el)
    log.scrollTop = log.scrollHeight
  }

  client.on('ready', () => {
    dot.classList.add('on')
    input.disabled = false
    button.disabled = false
    device.textContent = client.deviceId ?? '?'
    input.focus()
  })
  client.on('disconnected', () => dot.classList.remove('on'))
  client.on('message', addBubble)
  client.on('error', (err) => console.warn(`[${userId}]`, err.message))

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
document.getElementById('reset')!.addEventListener('click', () => {
  panels.forEach((p) => p.client.disconnect())
  const req = indexedDB.deleteDatabase('encra-v1')
  req.onsuccess = req.onerror = req.onblocked = () => window.location.reload()
})
