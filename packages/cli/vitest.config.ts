import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@encra/core': resolve(__dirname, '../core/dist/index.js'),
    },
  },
  test: {
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/index.ts'],
      thresholds: {
        lines:      85,
        statements: 85,
        // Functions/branches are lower because print.ts contains TTY-specific
        // interval/stdout code that is only reachable in a real terminal environment
        // and cannot be exercised in a non-TTY test runner.
        functions:  70,
        branches:   65,
      },
    },
  },
})
