import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { dictionarySplit } from './dictionarySplit';

export default defineConfig({
  plugins: [react(), dictionarySplit(fileURLToPath(new URL('.', import.meta.url)))],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: [
      'src/**/*.test.{ts,tsx}',
      'bundleGuard.test.ts',
      'fontCoverage.test.ts',
      'screenIntegrity.test.ts',
      'firstScreenPreload.test.ts',
      'factKeySource.test.ts',
      'dictionarySplit.test.ts',
    ],
  },
});
