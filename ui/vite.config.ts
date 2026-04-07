import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // Tauri expects a fixed port in development
  server: {
    port: 1420,
    strictPort: true,
  },
  // Env vars exposed to the frontend
  envPrefix: ['VITE_', 'TAURI_'],
});
