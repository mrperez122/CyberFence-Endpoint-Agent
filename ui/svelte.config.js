import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/kit/vite';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    // Static adapter — Tauri loads the built files directly
    adapter: adapter({
      fallback: 'index.html',
    }),
  },
};

export default config;
