import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const apiTarget = process.env.QG_API ?? 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    port: Number(process.env.QG_WEB_PORT ?? 5173),
    strictPort: true,
    proxy: { '/api': apiTarget, '/healthz': apiTarget },
  },
  build: { target: 'es2023', sourcemap: false },
})
