import { vi } from 'vitest'

// Prevent jsdom from replacing the Node.js Uint8Array global.
// libsodium captures Uint8Array at load time; jsdom's later replacement
// breaks instanceof checks inside the crypto library.
const NodeUint8Array = Uint8Array
vi.stubGlobal('Uint8Array', NodeUint8Array)
