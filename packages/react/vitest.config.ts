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
    environment: 'jsdom',
    setupFiles: ['./test-setup.ts'],
    server: {
      deps: {
        // Inline libsodium so it runs in the same jsdom realm as the tests,
        // preventing the cross-realm Uint8Array instanceof mismatch.
        // The alias above ensures the CJS build is used (not the broken ESM one).
        inline: [/libsodium/, /@encra\/core/],
      },
    },
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/index.ts'],
      // Branch threshold is 70% (not 90%) because:
      //  1. ratchetStore.ts lines 24-33 (the openDB call) are unreachable in jsdom —
      //     jsdom has no IndexedDB implementation, so getDB() always takes the early-
      //     return path and those branches are permanently uncoverable here.
      //  2. The decrypt success path requires a valid shared secret which depends on
      //     matching key pairs — full coverage lives in the Alice→Bob integration test
      //     in packages/server.
      thresholds: { lines: 85, functions: 85, branches: 70, statements: 85 },
    },
  },
})
