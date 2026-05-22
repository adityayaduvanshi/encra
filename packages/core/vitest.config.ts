import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
  resolve: {
    // libsodium-wrappers ESM build references a missing libsodium.mjs — use CJS build instead
    alias: {
      'libsodium-wrappers': resolve(
        __dirname,
        '../../node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js'
      ),
    },
  },
  test: {
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/index.ts'],
      thresholds: { lines: 90, functions: 90, branches: 90, statements: 90 },
    },
  },
})
