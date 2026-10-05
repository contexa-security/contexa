import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Browser, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * P4-FE-01, P4-BE-01, P4-BE-03 and P4-BE-04 on a real portal with live runs on (p3-restart-portal-dev.sh with
 * SHOWCASE_LIVE_MAX_CONCURRENT=1 and SHOWCASE_LIVE_VISITOR_DAILY=1): a new cell runs live and fills the map with the
 * engine's own verdict, the next visitor of that cell sees the stored run and its time, a second live run waits in the
 * queue, and a visitor's second new cell meets the daily limit. Runs only with SHOWCASE_LIVE_EXPLORE=1.
 */
test.skip(process.env.SHOWCASE_LIVE_EXPLORE !== '1', 'needs a portal with live runs and lowered limits');
test.describe.configure({ mode: 'serial' });

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

const RUN_TIMEOUT = 180_000;

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => violation.id);
}

/** Opens the map of Engineer K, a matching ticket and a new device, and returns the labels of cells not run yet. */
async function openMap(page: Page) {
  await page.goto('/explore?lng=en');
  await page.getByRole('button', { name: 'Engineer K' }).click();
  await page.getByRole('button', { name: 'Matches' }).click();
  await page.getByRole('button', { name: 'New device' }).click();
  await expect(page.getByRole('button', { name: / · (Not run|Allowed|Blocked|Verify|Under review|Pending)$/ }).first())
    .toBeVisible();
  const cells = page.getByRole('button', { name: / · Not run$/ });
  const labels: string[] = [];
  for (const cell of await cells.all()) {
    labels.push((await cell.getAttribute('aria-label')) ?? '');
  }
  return labels;
}

async function visitor(browser: Browser) {
  const context = await browser.newContext();
  return context.newPage();
}

let firstCell = '';

test('a new cell runs live and the map shows the engine verdict of that run', async ({ page }, info) => {
  test.skip(info.project.name !== 'chromium', 'live runs are checked once');
  test.setTimeout(2 * RUN_TIMEOUT);
  const open = await openMap(page);
  test.skip(open.length < 3, 'not enough cells left to run on this map');
  firstCell = open[0] ?? '';
  await page.getByRole('button', { name: firstCell }).click();
  await expect(page.getByText('No one has run this combination yet.')).toBeVisible();
  await expect(page.getByText('Live runs left today: 1/1')).toBeVisible();
  expect(await seriousViolations(page)).toEqual([]);
  await page.getByRole('button', { name: 'Run this combination' }).click();

  await expect(page.getByText(/Real run record · .*UTC/)).toBeVisible({ timeout: RUN_TIMEOUT });
  const filled = page.getByRole('button', { name: new RegExp(`^${firstCell.replace(' · Not run', '')} · `) });
  await expect(filled).not.toHaveAttribute('aria-label', firstCell);
  if (evidenceDir) {
    await page.screenshot({ path: join(evidenceDir, 'explore-recorded.png'), fullPage: true });
  }
});

test('the next visitor of the same cell sees the stored run and its time without a new run', async ({ browser }) => {
  test.skip(firstCell === '', 'the first live run did not happen');
  const page = await visitor(browser);
  await openMap(page);
  await page.getByRole('button', { name: new RegExp(`^${firstCell.replace(' · Not run', '')} · `) }).click();
  await expect(page.getByText(/Real run record · .*UTC/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Run this combination' })).toHaveCount(0);
});

test('a second live run waits in the queue and a second new cell meets the daily limit', async ({ browser }) => {
  test.skip(firstCell === '', 'the first live run did not happen');
  test.setTimeout(4 * RUN_TIMEOUT);
  const first = await visitor(browser);
  const second = await visitor(browser);
  const firstOpen = await openMap(first);
  await openMap(second);
  const [cellA, cellB, cellC] = firstOpen;
  test.skip(!cellA || !cellB || !cellC, 'not enough cells left to run on this map');

  await first.getByRole('button', { name: cellA ?? '' }).click();
  await first.getByRole('button', { name: 'Run this combination' }).click();
  await expect(first.locator('#run-title')).toBeVisible({ timeout: 30_000 });
  await second.getByRole('button', { name: cellB ?? '' }).click();
  await second.getByRole('button', { name: 'Run this combination' }).click();
  await expect(second.getByText(/Number 1 in line/)).toBeVisible({ timeout: 30_000 });
  if (evidenceDir) {
    await second.screenshot({ path: join(evidenceDir, 'explore-queued.png'), fullPage: true });
  }
  await expect(first.getByText(/Real run record · .*UTC/)).toBeVisible({ timeout: RUN_TIMEOUT });
  await expect(second.getByText(/Real run record · .*UTC/)).toBeVisible({ timeout: RUN_TIMEOUT });

  await first.getByRole('button', { name: cellC ?? '' }).click();
  await first.getByRole('button', { name: 'Run this combination' }).click();
  await expect(first.getByText("You have used all of today's live runs.")).toBeVisible();
  if (evidenceDir) {
    await first.screenshot({ path: join(evidenceDir, 'explore-daily-limit.png'), fullPage: true });
  }
});
