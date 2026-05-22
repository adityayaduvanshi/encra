import inquirer from 'inquirer'
import chalk from 'chalk'
import fs from 'fs-extra'
import path from 'path'

interface InitAnswers {
  projectName: string
  framework: 'node' | 'react' | 'react-native'
  serverUrl: string
}

const ENV_TEMPLATE = (serverUrl: string) => `# Encra configuration
E2E_SERVER_URL=${serverUrl}
E2E_API_KEY=e2e_live_your_key_here
`

const NODE_SNIPPET = (serverUrl: string) => `import { E2EChat } from '@encra/core'
import { generateKeyPair, exportKey, deriveSharedSecret, encrypt, decrypt } from '@encra/core'

// 1. Register user
const keyPair = await generateKeyPair()
const res = await fetch('${serverUrl}/v1/keys', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + process.env.E2E_API_KEY },
  body: JSON.stringify({ userId: 'alice', publicKey: exportKey(keyPair.publicKey) }),
})

// 2. Send an encrypted message to bob
const bobRes = await fetch('${serverUrl}/v1/keys/bob', {
  headers: { Authorization: 'Bearer ' + process.env.E2E_API_KEY },
})
const { publicKey: bobPubB64 } = await bobRes.json()
const sharedSecret = await deriveSharedSecret(keyPair.privateKey, importKey(bobPubB64))
const { ciphertext, nonce } = await encrypt('Hello Bob!', sharedSecret)
`

const REACT_SNIPPET = () => `import { useE2EChat } from '@encra/react'

function Chat() {
  const { messages, isReady, sendMessage, error } = useE2EChat({
    apiKey: process.env.REACT_APP_E2E_API_KEY!,
    userId: 'alice',
    serverUrl: process.env.REACT_APP_E2E_SERVER_URL!,
  })

  return (
    <div>
      {messages.map((m, i) => <p key={i}>{m.from}: {m.text}</p>)}
      <button onClick={() => sendMessage('bob', 'Hello!')}>Send</button>
    </div>
  )
}
`

export async function runInit(outputDir = process.cwd()): Promise<void> {
  console.log(chalk.bold.cyan('\n  Encra — Setup Wizard\n'))

  const answers = await inquirer.prompt<InitAnswers>([
    {
      type: 'input',
      name: 'projectName',
      message: 'Project name:',
      default: path.basename(process.cwd()),
    },
    {
      type: 'list',
      name: 'framework',
      message: 'Framework:',
      choices: [
        { name: 'Node.js', value: 'node' },
        { name: 'React', value: 'react' },
        { name: 'React Native', value: 'react-native' },
      ],
    },
    {
      type: 'input',
      name: 'serverUrl',
      message: 'Key server URL:',
      default: 'http://localhost:3000',
    },
  ])

  // Write .env.example
  await fs.outputFile(path.join(outputDir, '.env.example'), ENV_TEMPLATE(answers.serverUrl))

  // Write starter snippet
  const snippetFile = answers.framework === 'react' || answers.framework === 'react-native'
    ? 'e2e-chat-example.tsx'
    : 'e2e-chat-example.ts'

  const snippet = answers.framework === 'react' || answers.framework === 'react-native'
    ? REACT_SNIPPET()
    : NODE_SNIPPET(answers.serverUrl)

  await fs.outputFile(path.join(outputDir, snippetFile), snippet)

  console.log(chalk.green('\n  ✓ Created .env.example'))
  console.log(chalk.green(`  ✓ Created ${snippetFile}`))
  console.log(chalk.yellow('\n  Next steps:'))
  console.log('    1. Copy .env.example to .env and fill in your API key')
  console.log('    2. Start the key server: cd packages/server && npm start')
  console.log(`    3. Open ${snippetFile} to see your starter code`)
  console.log(chalk.dim('\n  Docs: https://github.com/adityayaduvanshi/encra\n'))
}
