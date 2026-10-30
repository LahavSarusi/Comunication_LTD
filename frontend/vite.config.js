import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Fail instead of silently moving to another port: the backend's CORS
    // allowlist (CORS_ORIGIN in backend/.env) only accepts this exact origin.
    strictPort: true,
  },
})
