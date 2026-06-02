import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
  resolve: {
    alias: {
      'libsodium-wrappers': resolve(
        __dirname,
        '../../node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js'
      ),
      '@encra/core': resolve(__dirname, '../core/dist/index.js'),
    },
  },
  test: {
    // Node (not jsdom): the chat path round-trips Uint8Arrays through libsodium,
    // and jsdom introduces a second Uint8Array realm that fails libsodium's
    // internal instanceof checks. Node 22 provides File/Blob, the IndexedDB
    // paths are guarded for non-browser environments, and WebSocket is mocked,
    // so no DOM is required here.
    environment: 'node',
    server: {
      deps: {
        inline: [/libsodium/, /@encra\/core/],
      },
    },
    coverage: {
      provider: 'v8',
      include:  ['src/**'],
      exclude:  ['src/index.ts'],
      // Branch threshold is 65% — IndexedDB persistence paths are unreachable
      // outside a browser; the decrypt success path is covered by the in-suite
      // Alice→Bob X3DH end-to-end test.
      thresholds: { lines: 80, functions: 80, branches: 65, statements: 80 },
    },
  },
})
