import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { crx } from '@crxjs/vite-plugin'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)
const manifest = require('./manifest.json')

export default defineConfig({
  plugins: [react(), crx({ manifest })],
  build: {
    rollupOptions: {
      input: {
        popup: 'src/popup/popup.html',
        dashboard: 'src/dashboard/dashboard.html',
      },
    },
  },
})