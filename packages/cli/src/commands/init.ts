import inquirer from 'inquirer'
import chalk from 'chalk'
import fs from 'fs-extra'
import path from 'path'
import { detectFramework, detectPackageManager } from '../utils/detect.js'
import {
  envTemplate,
  nextjsSnippet,
  reactSnippet,
  reactNativeSnippet,
  nodeSnippet,
} from '../utils/snippets.js'
import { s, divider } from '../utils/print.js'
import type { Framework } from '../utils/detect.js'

const FRAMEWORK_LABEL: Record<Framework, string> = {
  nextjs:          'Next.js',
  react:           'React  (Vite / CRA)',
  'react-native':  'React Native / Expo',
  node:            'Node.js',
}

const INSTALL_CMD: Record<string, string> = {
  npm:  'npm install',
  yarn: 'yarn add',
  pnpm: 'pnpm add',
  bun:  'bun add',
}

const SDK_PKG: Record<Framework, string> = {
  nextjs:          '@encra/react',
  react:           '@encra/react',
  'react-native':  '@encra/react',
  node:            '@encra/core',
}

const SNIPPET_FILE: Record<Framework, string> = {
  nextjs:          'components/encra-chat.tsx',
  react:           'src/components/EncraChat.tsx',
  'react-native':  'components/EncraChat.tsx',
  node:            'encra-example.ts',
}

interface InitAnswers {
  framework: Framework
  apiKey: string
  serverUrl: string
  overwrite?: boolean
}

/**
 * Interactive setup wizard.
 * Detects your framework, writes .env.example, and generates a working starter component.
 *
 * @param outputDir - Directory to write files into (defaults to cwd).
 */
export async function runInit(outputDir = process.cwd()): Promise<void> {
  console.log()
  console.log(chalk.bold('  encra') + chalk.dim(' — setup wizard'))
  divider()
  console.log()

  // Auto-detect framework + package manager
  const detectedFramework = await detectFramework(outputDir)
  const detectedPm        = await detectPackageManager(outputDir)

  if (detectedFramework !== 'node') {
    console.log(
      `  ${chalk.dim('Detected:')}  ${chalk.cyan(FRAMEWORK_LABEL[detectedFramework])}` +
      `  ${chalk.dim('·')}  ${chalk.dim(detectedPm)}`,
    )
    console.log()
  }

  const envPath   = path.join(outputDir, '.env.example')
  const envExists = await fs.pathExists(envPath)

  const answers = await inquirer.prompt<InitAnswers>([
    {
      type:    'list',
      name:    'framework',
      message: 'Framework:',
      default: detectedFramework,
      choices: [
        { name: 'Next.js',              value: 'nextjs'         },
        { name: 'React  (Vite / CRA)',  value: 'react'          },
        { name: 'React Native / Expo',  value: 'react-native'   },
        { name: 'Node.js',              value: 'node'           },
      ],
    },
    {
      type:    'password',
      name:    'apiKey',
      message: `API key ${chalk.dim('(optional — press enter to skip):')}`,
      default: '',
      mask:    '*',
    },
    {
      type:    'input',
      name:    'serverUrl',
      message: `Server URL ${chalk.dim('(enter to use Encra managed server):')}`,
      default: 'https://api.encra.dev',
    },
    {
      type:    'confirm',
      name:    'overwrite',
      message: '.env.example already exists — overwrite?',
      default: false,
      when:    () => envExists,
    },
  ])

  console.log()

  // ── Write .env.example ────────────────────────────────────────────
  const shouldWriteEnv = !envExists || answers.overwrite === true
  if (shouldWriteEnv) {
    await fs.outputFile(envPath, envTemplate(answers.framework, answers.serverUrl, answers.apiKey))
    console.log(`  ${s.ok}  Created  ${chalk.bold('.env.example')}`)
  } else {
    console.log(`  ${s.skip}  Skipped  ${chalk.dim('.env.example')} ${chalk.dim('(already exists)')}`)
  }

  // ── Write starter component ───────────────────────────────────────
  const snippetFile = SNIPPET_FILE[answers.framework]!
  const snippetPath = path.join(outputDir, snippetFile)

  let snippet: string
  switch (answers.framework) {
    case 'nextjs':         snippet = nextjsSnippet(); break
    case 'react':          snippet = reactSnippet(); break
    case 'react-native':   snippet = reactNativeSnippet(); break
    default:               snippet = nodeSnippet(answers.serverUrl)
  }

  await fs.outputFile(snippetPath, snippet)
  console.log(`  ${s.ok}  Created  ${chalk.bold(snippetFile)}`)

  // ── Next steps ────────────────────────────────────────────────────
  const pm         = detectedPm
  const installCmd = `${INSTALL_CMD[pm] ?? 'npm install'} ${SDK_PKG[answers.framework]}`
  const pingCmd    = answers.apiKey
    ? `npx encra ping --api-key ${answers.apiKey}`
    : 'npx encra ping'

  let step = 1
  console.log()
  console.log(chalk.bold('  Next steps'))
  console.log()

  console.log(`  ${chalk.dim(`${step++}.`)}  Install the SDK:`)
  console.log(`       ${chalk.cyan(installCmd)}`)
  console.log()

  if (shouldWriteEnv) {
    console.log(`  ${chalk.dim(`${step++}.`)}  Copy ${chalk.bold('.env.example')} → ${chalk.bold('.env')} and fill in your API key:`)
    console.log(`       ${chalk.dim('cp .env.example .env')}`)
    console.log()
  }

  console.log(`  ${chalk.dim(`${step++}.`)}  Add the component to your app:`)
  console.log(`       ${chalk.dim(`Open ${snippetFile}`)}`)
  console.log()

  console.log(`  ${chalk.dim(`${step}.`)}  Verify your connection:`)
  console.log(`       ${chalk.cyan(pingCmd)}`)
  console.log()

  divider()
  console.log(`  ${chalk.dim('Docs:')}   ${chalk.underline('https://encra.dev/docs')}`)
  console.log()
}
