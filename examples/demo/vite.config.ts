import { defineConfig } from 'vite'
import type { Plugin } from 'vite'
import { fileURLToPath, URL } from 'node:url'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { mockRelay } from './mock-relay'

const here = fileURLToPath(new URL('.', import.meta.url))

// libsodium-wrappers' ESM build does `import './libsodium.mjs'`, but that file
// actually lives in the sibling `libsodium` package (and its package `exports`
// map hides the subpath, so require.resolve can't reach it). Point at the file
// directly, checking the demo's own node_modules and the hoisted root one.
function libsodiumFix(): Plugin {
  const rel = 'dist/modules-esm/libsodium.mjs'
  const target = [
    path.resolve(here, 'node_modules/libsodium', rel),
    path.resolve(here, '../../node_modules/libsodium', rel),
  ].find(existsSync)
  return {
    name: 'libsodium-fix',
    enforce: 'pre',
    resolveId(id, importer) {
      if (target && id === './libsodium.mjs' && importer?.includes('libsodium-wrappers')) return target
    },
  }
}

// Run the SDK straight from TypeScript source (no build step, always current).
// The packages use NodeNext-style `.js` import specifiers that point at `.ts`
// files; this plugin maps them back to source for Vite's dev resolver.
function tsSourceResolve(): Plugin {
  return {
    name: 'encra-ts-source',
    enforce: 'pre',
    resolveId(id, importer) {
      if (!importer || !id.startsWith('.') || !id.endsWith('.js')) return
      if (!/[\\/]packages[\\/](client|core)[\\/]src[\\/]/.test(importer)) return
      const ts = path.resolve(path.dirname(importer), id.replace(/\.js$/, '.ts'))
      if (existsSync(ts)) return ts
    },
  }
}

export default defineConfig({
  plugins: [mockRelay(), libsodiumFix(), tsSourceResolve()],
  resolve: {
    alias: {
      '@encra/client': fileURLToPath(new URL('../../packages/client/src/index.ts', import.meta.url)),
      '@encra/core':   fileURLToPath(new URL('../../packages/core/src/index.ts', import.meta.url)),
    },
  },
  optimizeDeps: { exclude: ['libsodium-wrappers', 'libsodium'] },
  build: { target: 'esnext' },
  server: {
    port: 5280,
    fs: { allow: ['../..'] },  // serve the monorepo's hoisted node_modules + source
  },
})
