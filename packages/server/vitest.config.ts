import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
  resolve: {
    alias: {
      // libsodium-wrappers ESM build references a missing libsodium.mjs — use CJS build
      'libsodium-wrappers': resolve(
        __dirname,
        '../../node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js'
      ),
      // Resolve workspace package directly to avoid Vite's package entry lookup issues
      '@encra/core': resolve(__dirname, '../core/dist/index.js'),
    },
  },
  test: {
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/index.ts'],
      thresholds: { lines: 90, functions: 90, branches: 85, statements: 90 },
    },
    env: {
      JWT_SECRET: 'test-secret-do-not-use-in-production',
    },
  },
})
