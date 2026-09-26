/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Backend URL used by the dev-server proxy (browser calls stay same-origin).
const BACKEND_URL = process.env.VITE_BACKEND_URL ?? 'http://127.0.0.1:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': BACKEND_URL,
      '/health': BACKEND_URL,
    },
  },
  test: {
    environment: 'jsdom',
    // Worker threads start reliably on Windows; the default child-process
    // pool timed out during worker startup in this environment.
    pool: 'threads',
    setupFiles: ['./src/test/setup.ts'],
  },
})
