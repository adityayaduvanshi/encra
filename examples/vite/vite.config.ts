import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import type { Plugin } from 'vite'

// libsodium-wrappers ESM build does `import './libsodium.mjs'` as a relative
// import, but that file lives in the *sibling* `libsodium` package.
//
// Fix strategy:
//   - exclude both from optimizeDeps so esbuild never tries to bundle them
//   - intercept the relative import with a pre-enforced Vite plugin so the
//     dev-server module graph resolves it correctly at request time
function libsodiumFixPlugin(): Plugin {
  return {
    name: 'libsodium-fix',
    enforce: 'pre',   // run before Vite's own resolver in dev mode
    resolveId(id: string, importer: string | undefined) {
      if (id === './libsodium.mjs' && importer?.includes('libsodium-wrappers')) {
        return path.resolve(__dirname, 'node_modules/libsodium/dist/modules-esm/libsodium.mjs')
      }
    },
  }
}

// Point directly at the monorepo source so the playground always runs the
// latest code without needing a build step or a separate npm install.
export default defineConfig({
  plugins: [react(), libsodiumFixPlugin()],
  resolve: {
    alias: {
      '@encra/react': path.resolve(__dirname, '../../packages/react/src/index.ts'),
      '@encra/core':  path.resolve(__dirname, '../../packages/core/src/index.ts'),
    },
  },
  optimizeDeps: {
    // Don't let esbuild pre-bundle libsodium — it can't resolve the relative
    // ./libsodium.mjs cross-package import. Serve the ESM files raw instead;
    // the libsodiumFixPlugin above handles the redirect at request time.
    exclude: ['libsodium-wrappers', 'libsodium'],
  },
  build: {
    // libsodium.mjs uses top-level await — requires modern browser targets
    target: 'esnext',
  },
  server: {
    fs: {
      // Allow Vite to serve files from outside the playground root
      allow: ['../..'],
    },
  },
})
