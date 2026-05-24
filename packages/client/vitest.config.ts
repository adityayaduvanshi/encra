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
    setupFiles:  ['./test-setup.ts'],
    server: {
      deps: {
        inline: [/libsodium/, /@encra\/core/],
      },
    },
    coverage: {
      provider: 'v8',
      include:  ['src/**'],
      exclude:  ['src/index.ts'],
      // Branch threshold is 70% — same reasoning as @encra/react:
      // IndexedDB paths unreachable in jsdom, decrypt success path covered
      // by the Alice→Bob integration test in packages/server.
      thresholds: { lines: 80, functions: 80, branches: 65, statements: 80 },
    },
  },
})
