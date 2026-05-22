import chalk from 'chalk'
import { spinner, s } from '../utils/print.js'

async function fetchWithTimeout(url: string, init: RequestInit, ms: number): Promise<Response> {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), ms)
  try {
    return await fetch(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(id)
  }
}

/**
 * Check whether the Encra server is reachable and (optionally) whether the
 * supplied API key is valid.
 *
 * @param serverUrl - Base URL of the server to check.
 * @param apiKey    - Optional JWT to test authentication.
 */
export async function runPing(serverUrl: string, apiKey?: string): Promise<void> {
  const url = serverUrl.replace(/\/$/, '')

  console.log()
  console.log(`  ${chalk.bold('Checking')} ${chalk.cyan(url)}`)
  console.log()

  // ── 1. HTTP health check ─────────────────────────────────────────
  const httpSpin = spinner('HTTP health check')
  let httpOk = false

  try {
    const start = Date.now()
    const res   = await fetchWithTimeout(`${url}/health`, {}, 5000)
    const ms    = Date.now() - start

    if (res.ok) {
      httpOk = true
      httpSpin.succeed(`HTTP     ${chalk.green(`${res.status} OK`)}  ${chalk.dim(`${ms}ms`)}`)
    } else {
      httpSpin.fail(`HTTP     ${res.status} ${res.statusText}`)
    }
  } catch (err: unknown) {
    const isTimeout = err instanceof Error && err.name === 'AbortError'
    const msg       = isTimeout ? 'timed out after 5s'
      : err instanceof Error ? err.message
      : 'connection refused'
    httpSpin.fail(`HTTP     ${msg}`)

    console.log()
    console.log(`  ${chalk.dim('Tip: make sure your server is running at')} ${url}`)
    console.log(`       ${chalk.dim('Run:  npx encra ping --server <url>')}`)
    console.log()
    return
  }

  // ── 2. Auth check ────────────────────────────────────────────────
  if (apiKey) {
    const authSpin = spinner('Auth check')
    try {
      const res = await fetchWithTimeout(
        `${url}/v1/keys/__ping_probe__`,
        { headers: { Authorization: `Bearer ${apiKey}` } },
        5000,
      )

      // 404 = user not found but token was accepted → auth is working
      if (res.status === 404 || res.ok) {
        authSpin.succeed(`Auth     ${chalk.green('token accepted')}`)
      } else if (res.status === 401) {
        authSpin.fail(`Auth     invalid API key — check ENCRA_API_KEY in your .env`)
      } else {
        authSpin.fail(`Auth     unexpected ${res.status}`)
      }
    } catch {
      authSpin.fail('Auth     request failed')
    }
  } else {
    console.log(`  ${s.skip}  Auth     ${chalk.dim('no API key provided')}  ${chalk.dim('(use --api-key to test)')}`)
  }

  console.log()
  if (httpOk) {
    console.log(`  ${chalk.green('Server is healthy.')} ${chalk.dim("You're good to go.")}`)
  }
  console.log()
}
