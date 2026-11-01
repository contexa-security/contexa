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
      'sourceExcerpts.test.ts',
      'screenIntegrity.test.ts',
      'firstScreenPreload.test.ts',
      'factWordsSource.test.ts',
      'factKeySource.test.ts',
      'benchPromptPhone.test.ts',
      'dictionarySplit.test.ts',
      'frameStyles.test.ts',
      'e2e/guideCaptions.test.mjs',
      'e2e/guide/*.test.mjs',
    ],
  },
});
