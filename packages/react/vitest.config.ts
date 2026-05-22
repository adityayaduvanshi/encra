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
      // Branch threshold is 75% (not 90%) because the success paths of decrypt and
      // sendMessage both require real libsodium crypto, which fails in the jsdom
      // cross-realm Uint8Array environment. Those paths are covered by the Alice→Bob
      // integration test in packages/server.
      thresholds: { lines: 85, functions: 85, branches: 75, statements: 85 },
    },
  },
})
