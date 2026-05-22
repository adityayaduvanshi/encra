import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import path from 'path'
import os from 'os'
import fs from 'fs-extra'

// ── Mock inquirer so tests don't block on stdin ──────────────────────────────

vi.mock('inquirer', () => ({
  default: {
    prompt: vi.fn(),
  },
}))

vi.mock('chalk', () => ({
  default: {
    bold: Object.assign((s: string) => s, {
      cyan: (s: string) => s,
    }),
    green: (s: string) => s,
    yellow: (s: string) => s,
    red: (s: string) => s,
    cyan: (s: string) => s,
    dim: (s: string) => s,
  },
}))

// ── Tests ────────────────────────────────────────────────────────────────────

describe('init command', () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'e2e-cli-test-'))
  })

  afterEach(async () => {
    await fs.remove(tmpDir)
    vi.restoreAllMocks()
  })

  it('creates .env.example and Node.js snippet for node framework', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      projectName: 'my-app',
      framework: 'node',
      serverUrl: 'http://localhost:3000',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    expect(await fs.pathExists(path.join(tmpDir, '.env.example'))).toBe(true)
    expect(await fs.pathExists(path.join(tmpDir, 'e2e-chat-example.ts'))).toBe(true)

    const env = await fs.readFile(path.join(tmpDir, '.env.example'), 'utf8')
    expect(env).toContain('E2E_SERVER_URL=http://localhost:3000')
    expect(env).toContain('E2E_API_KEY')

    const snippet = await fs.readFile(path.join(tmpDir, 'e2e-chat-example.ts'), 'utf8')
    expect(snippet).toContain('generateKeyPair')
  })

  it('creates React snippet for react framework', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      projectName: 'my-react-app',
      framework: 'react',
      serverUrl: 'https://api.example.com',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    expect(await fs.pathExists(path.join(tmpDir, 'e2e-chat-example.tsx'))).toBe(true)
    const snippet = await fs.readFile(path.join(tmpDir, 'e2e-chat-example.tsx'), 'utf8')
    expect(snippet).toContain('useE2EChat')
  })

  it('creates React Native tsx snippet', async () => {
    const inquirer = (await import('inquirer')).default
    vi.mocked(inquirer.prompt).mockResolvedValueOnce({
      projectName: 'my-rn-app',
      framework: 'react-native',
      serverUrl: 'https://api.example.com',
    })

    const { runInit } = await import('../src/commands/init.js')
    await runInit(tmpDir)

    expect(await fs.pathExists(path.join(tmpDir, 'e2e-chat-example.tsx'))).toBe(true)
  })
})

describe('keygen command', () => {
  it('prints a public and private key', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const { runKeygen } = await import('../src/commands/keygen.js')
    await runKeygen()

    const output = consoleSpy.mock.calls.flat().join('\n')
    // Keys are base64url encoded — they'll contain letters and numbers, possibly - and _
    expect(output).toMatch(/[A-Za-z0-9_-]{40,}/) // public key
    expect(consoleSpy.mock.calls.length).toBeGreaterThan(3)
  })
})
