import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { internalAddressGuard } from './bundleGuard';
import { firstScreenPreload } from './firstScreenPreload';
import { languagePreload } from './languagePreload';
import { precompress } from './precompress';

// The production bundle is served by showcase-portal; the dev server proxies API calls to it.
export default defineConfig({
  plugins: [react(), internalAddressGuard(), languagePreload(), firstScreenPreload(), precompress()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rolldownOptions: {
      output: {
        codeSplitting: {
          // C-13: the small parts the try steps share with the lab and the details travel as one chunk (and one style
          // file), so a try step opened from its address reads a few files instead of eleven. Only these modules, and
          // only ones every screen that reads this chunk already needed: their other dependencies stay where they are.
          groups: [
            {
              name: 'try-parts',
              test: /[\\/]src[\\/](domain[\\/](verdict|live)\.ts|pages[\\/]try[\\/](decision\.tsx|Experience\.module\.css|steps[\\/](liveRun|LiveRunBar)\.tsx)|components[\\/](inside[\\/](Comparison\.tsx|InsidePanel\.(tsx|module\.css)|insideCells\.ts)|VerdictChip\.(tsx|module\.css)|journey[\\/]flow\.tsx|(LiveChallenge|ChallengePanel|RecoveryFlow)\.(tsx|module\.css))|hooks[\\/](useLiveSend|useTurnstile)\.ts|api[\\/]engine\.ts)$/,
              includeDependenciesRecursively: false,
            },
          ],
        },
      },
    },
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
