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
      // index.ts: entry point with graceful-shutdown signal handlers (not unit-testable)
      // redis.ts:  thin ioredis adapter; exercised only with a real Redis instance
      exclude: ['src/index.ts', 'src/redis.ts'],
      // Thresholds set to match @encra/react / @encra/client targets.
      // Infra-only paths (Redis pub/sub, pinoHttp in non-test env, DB pool
      // creation, graceful-shutdown signal handlers) are deliberately excluded
      // from unit testing — they require real external services or process signals.
      thresholds: { lines: 85, functions: 85, branches: 70, statements: 85 },
    },
    env: {
      JWT_SECRET: 'test-secret-do-not-use-in-production',
    },
  },
})
