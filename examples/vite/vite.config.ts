import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: ['libsodium-wrappers'],
  },
  resolve: {
    alias: {
      'libsodium-wrappers': path.resolve(__dirname, '../../node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js'),
      '@encra/react': path.resolve(__dirname, '../../packages/react/src/index.ts'),
      '@encra/core':  path.resolve(__dirname, '../../packages/core/src/index.ts'),
    },
  },
})
