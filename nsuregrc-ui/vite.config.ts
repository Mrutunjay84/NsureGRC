import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import basicSsl from '@vitejs/plugin-basic-ssl'
import { defineConfig } from 'vite'

// D-P6-001: HTTPS + a same-origin-from-the-browser's-perspective proxy to the Django dev server
// (scripts/dev_run_https.py, https://127.0.0.1:8443) - keeps the existing Secure cookie / CSRF
// setup working unmodified (no CORS, no token storage). The backend's self-signed dev cert is
// accepted here with `secure: false`; that is a dev-only trust decision, not a production setting.
export default defineConfig({
  plugins: [react(), tailwindcss(), basicSsl()],
  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': { target: 'https://127.0.0.1:8443', changeOrigin: true, secure: false },
      '/healthz': { target: 'https://127.0.0.1:8443', changeOrigin: true, secure: false },
    },
  },
})
