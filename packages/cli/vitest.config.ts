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
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/index.ts'],
      thresholds: { lines: 85, functions: 85, branches: 80, statements: 85 },
    },
  },
})
