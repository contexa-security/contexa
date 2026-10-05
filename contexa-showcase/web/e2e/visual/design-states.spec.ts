import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Deck p.20 state screens on the development gallery: each state shows its plain sentence and its next actions in
 * Korean and English, with no serious accessibility violation and no horizontal scroll at phone width.
 */
const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

const EXPECTED: Record<string, { message: string; actions: string[] }> = {
  loading: { message: 'state.loading', actions: [] },
  error: { message: 'state.error', actions: ['state.retry'] },
  notReady: { message: 'state.notReady', actions: ['state.home'] },
  waiting: { message: 'state.waiting', actions: ['state.viewRecord'] },
  outage: { message: 'state.outage', actions: ['state.retry', 'state.viewRecord'] },
  challengeCancelled: { message: 'state.challengeCancelled', actions: ['state.retryChallenge', 'state.viewRecord'] },
  challengeExpired: { message: 'state.challengeExpired', actions: ['state.restart', 'state.viewRecord'] },
  dailyLimit: { message: 'state.dailyLimit', actions: ['state.viewRecord', 'state.signInMore'] },
  paused: { message: 'state.paused', actions: ['state.viewSameRecord', 'state.notifyTurn'] },
  recoveryFailed: { message: 'state.recoveryFailed', actions: ['state.resetRetry'] },
};

for (const language of ['ko', 'en'] as const) {
  for (const width of [1440, 390] as const) {
    test(`state screens ${language} ${width}`, async ({ page }) => {
      const words = JSON.parse(readFileSync(join(process.cwd(), `src/i18n/${language}.json`), 'utf-8')) as Record<
        string,
        string
      >;
      await page.setViewportSize({ width, height: 900 });
      await page.goto(`/design/states?lng=${language}`);
      for (const [kind, expected] of Object.entries(EXPECTED)) {
        const state = page.locator(`section[data-kind="${kind}"]`);
        await expect(state.getByText(words[expected.message] ?? 'missing', { exact: true })).toBeVisible();
        const actions = await state.locator('a, button').allTextContents();
        expect(actions, kind).toEqual(expected.actions.map((key) => words[key]));
      }
      await expect(page.locator('section[data-kind="recoveryFailed"] summary')).toHaveText(words['state.cause'] ?? '');
      for (const [sample, state, count] of [
        ['stream-cut', 'stream.state.cut', '412'],
        ['stream-done', 'stream.state.done', '600'],
        ['stream-interrupted', 'stream.state.interrupted', '96'],
      ] as const) {
        const meter = page.locator(`section[data-sample="${sample}"]`);
        await expect(meter.getByText(words[state] ?? 'missing', { exact: true })).toBeVisible();
        await expect(meter.getByTestId('stream-count')).toContainText(count);
      }
      const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
      expect(
        results.violations
          .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
          .map((violation) => violation.id),
      ).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
      if (evidenceDir) {
        await page.evaluate(() => document.fonts.ready);
        await page.screenshot({ path: join(evidenceDir, `states-${language}-${width}.png`), fullPage: true });
      }
    });
  }
}
