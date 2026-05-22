import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import path from 'path'
import os from 'os'
import fs from 'fs-extra'

// ── Mock inquirer so tests never block on stdin ───────────────────────────────
vi.mock('inquirer', () => ({
  default: { prompt: vi.fn() },
}))

// ── Mock chalk as identity functions (no ANSI codes in test output) ───────────
vi.mock('chalk', () => {
  const id = (s: string) => s
  const c = {
    bold:      Object.assign(id, { cyan: id, dim: id, red: id, green: id, yellow: id }),
    green:     Object.assign(id, { bold: id, dim: id }),
    yellow:    Object.assign(id, { bold: id, dim: id }),
    red:       Object.assign(id, { bold: id, dim: id }),
    cyan:      Object.assign(id, { bold: id, dim: id }),
    dim:       Object.assign(id, { bold: id, cyan: id }),
    underline: Object.assign(id, { bold: id }),
  }
  return { default: c }
})

// ─────────────────────────────────────────────────────────────────────────────

describe('init command', () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'encra-cli-test-'))
  })

  afterEach(async () => {
    await fs.remove(tmpDir)
    vi.restoreAllMocks()
  })

  it('creates .env.example and Node.js snippet for node framework', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      framework: 'node',
      apiKey:    '',
      serverUrl: 'http://localhost:3000',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    expect(await fs.pathExists(path.join(tmpDir, '.env.example'))).toBe(true)
    expect(await fs.pathExists(path.join(tmpDir, 'encra-example.ts'))).toBe(true)

    const env = await fs.readFile(path.join(tmpDir, '.env.example'), 'utf8')
    expect(env).toContain('ENCRA_API_KEY')
    expect(env).toContain('localhost:3000')

    const snippet = await fs.readFile(path.join(tmpDir, 'encra-example.ts'), 'utf8')
    expect(snippet).toContain('generateKeyPair')
    expect(snippet).toContain('DoubleRatchet')
    expect(snippet).toContain('@encra/core')
  })

  it('creates Next.js component and NEXT_PUBLIC_ env vars', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      framework: 'nextjs',
      apiKey:    '',
      serverUrl: 'https://api.encra.dev',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    expect(await fs.pathExists(path.join(tmpDir, 'components/encra-chat.tsx'))).toBe(true)

    const env = await fs.readFile(path.join(tmpDir, '.env.example'), 'utf8')
    expect(env).toContain('NEXT_PUBLIC_ENCRA_API_KEY')

    const snippet = await fs.readFile(path.join(tmpDir, 'components/encra-chat.tsx'), 'utf8')
    expect(snippet).toContain('useE2EChat')
    expect(snippet).toContain("'use client'")
    expect(snippet).toContain('NEXT_PUBLIC_ENCRA_API_KEY')
  })

  it('creates React component and VITE_ env vars for react framework', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      framework: 'react',
      apiKey:    '',
      serverUrl: 'https://api.encra.dev',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    expect(await fs.pathExists(path.join(tmpDir, 'src/components/EncraChat.tsx'))).toBe(true)

    const env = await fs.readFile(path.join(tmpDir, '.env.example'), 'utf8')
    expect(env).toContain('VITE_ENCRA_API_KEY')

    const snippet = await fs.readFile(path.join(tmpDir, 'src/components/EncraChat.tsx'), 'utf8')
    expect(snippet).toContain('useE2EChat')
    expect(snippet).toContain('VITE_ENCRA_API_KEY')
  })

  it('creates React Native component for react-native framework', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      framework: 'react-native',
      apiKey:    '',
      serverUrl: 'https://api.encra.dev',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    expect(await fs.pathExists(path.join(tmpDir, 'components/EncraChat.tsx'))).toBe(true)

    const snippet = await fs.readFile(path.join(tmpDir, 'components/EncraChat.tsx'), 'utf8')
    expect(snippet).toContain('useE2EChat')
    expect(snippet).toContain('EXPO_PUBLIC_ENCRA_API_KEY')
    expect(snippet).toContain('StyleSheet')
  })

  it('pre-fills API key in .env.example when provided', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      framework: 'node',
      apiKey:    'e2e_live_test123',
      serverUrl: 'http://localhost:3000',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    const env = await fs.readFile(path.join(tmpDir, '.env.example'), 'utf8')
    expect(env).toContain('ENCRA_API_KEY=e2e_live_test123')
  })

  it('does not overwrite existing .env.example when overwrite is false', async () => {
    // Write existing .env.example
    await fs.outputFile(path.join(tmpDir, '.env.example'), 'ORIGINAL=true\n')

    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      framework: 'node',
      apiKey:    '',
      serverUrl: 'http://localhost:3000',
      overwrite: false,
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    const env = await fs.readFile(path.join(tmpDir, '.env.example'), 'utf8')
    expect(env).toBe('ORIGINAL=true\n')
  })
})

// ─────────────────────────────────────────────────────────────────────────────

describe('keygen command', () => {
  it('prints a public key, private key, and fingerprint', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const { runKeygen } = await import('../src/commands/keygen.js')
    await runKeygen()

    const output = consoleSpy.mock.calls.flat().join('\n')
    // Keys are base64 (standard or url-safe) — 44 chars for a 32-byte key
    expect(output).toMatch(/[A-Za-z0-9+/=_-]{40,}/)
    expect(consoleSpy.mock.calls.length).toBeGreaterThan(3)
  })
})

// ─────────────────────────────────────────────────────────────────────────────

describe('detectFramework', () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'encra-detect-'))
  })
  afterEach(async () => {
    await fs.remove(tmpDir)
  })

  it('returns node when no package.json exists', async () => {
    const { detectFramework } = await import('../src/utils/detect.js')
    expect(await detectFramework(tmpDir)).toBe('node')
  })

  it('detects nextjs from dependencies', async () => {
    await fs.writeJson(path.join(tmpDir, 'package.json'), {
      dependencies: { next: '^14.0.0', react: '^18.0.0' },
    })
    const { detectFramework } = await import('../src/utils/detect.js')
    expect(await detectFramework(tmpDir)).toBe('nextjs')
  })

  it('detects react from dependencies', async () => {
    await fs.writeJson(path.join(tmpDir, 'package.json'), {
      dependencies: { react: '^18.0.0' },
    })
    const { detectFramework } = await import('../src/utils/detect.js')
    expect(await detectFramework(tmpDir)).toBe('react')
  })

  it('detects react-native from devDependencies', async () => {
    await fs.writeJson(path.join(tmpDir, 'package.json'), {
      devDependencies: { 'react-native': '^0.73.0' },
    })
    const { detectFramework } = await import('../src/utils/detect.js')
    expect(await detectFramework(tmpDir)).toBe('react-native')
  })

  it('detects package manager from lockfile', async () => {
    await fs.writeFile(path.join(tmpDir, 'pnpm-lock.yaml'), '')
    const { detectPackageManager } = await import('../src/utils/detect.js')
    expect(await detectPackageManager(tmpDir)).toBe('pnpm')
  })
})

// ─────────────────────────────────────────────────────────────────────────────

describe('ping command', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('reports healthy when server responds 200', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, statusText: 'OK' }))
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const { runPing } = await import('../src/commands/ping.js')
    await runPing('http://test-server:3000')

    const fetchMock = fetch as ReturnType<typeof vi.fn>
    expect(fetchMock).toHaveBeenCalledWith(
      'http://test-server:3000/health',
      expect.any(Object),
    )
    const output = consoleSpy.mock.calls.flat().join(' ')
    expect(output).toContain('healthy')
  })

  it('tests auth when api key is provided and returns 404 (accepted)', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })  // health
      .mockResolvedValueOnce({ ok: false, status: 404, statusText: 'Not Found' }) // auth probe
    )
    const stdoutSpy  = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    vi.spyOn(console, 'log').mockImplementation(() => {})

    const { runPing } = await import('../src/commands/ping.js')
    await runPing('http://test-server:3000', 'valid-api-key')

    const out = stdoutSpy.mock.calls.flat().join(' ')
    expect(out).toContain('token accepted')
  })

  it('reports 401 when api key is invalid', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
      .mockResolvedValueOnce({ ok: false, status: 401, statusText: 'Unauthorized' })
    )
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    vi.spyOn(console, 'log').mockImplementation(() => {})

    const { runPing } = await import('../src/commands/ping.js')
    await runPing('http://test-server:3000', 'bad-key')

    const out = stdoutSpy.mock.calls.flat().join(' ')
    expect(out).toContain('invalid API key')
  })

  it('reports failure when server is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')))
    // Spinner writes error via process.stdout.write in non-TTY mode
    const stdoutSpy  = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const { runPing } = await import('../src/commands/ping.js')
    await runPing('http://unreachable:9999')

    // Error text lands in stdout (spinner) or console.log (tip line)
    const all = [
      ...stdoutSpy.mock.calls.flat(),
      ...consoleSpy.mock.calls.flat(),
    ].join(' ')
    expect(all).toMatch(/ECONNREFUSED|connection refused|unreachable/i)
  })
})
