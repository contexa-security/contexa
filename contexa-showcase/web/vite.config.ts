import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { internalAddressGuard } from './bundleGuard';

// The production bundle is served by showcase-portal; the dev server proxies API calls to it.
export default defineConfig({
  plugins: [react(), internalAddressGuard()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5180,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:19180',
    },
  },
  preview: {
    port: 5181,
    strictPort: true,
  },
});
