import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * P3-BE-01 and P3-FE-01 on the development single space: a live run where control D asks for an additional check,
 * answered with the code from the demo inbox, cancelled and confirmed again, or failed with three wrong codes. Runs only
 * with SHOWCASE_LIVE_DEV=1 against a portal started with showcase.live.dev-space (p3-restart-portal-dev.sh); on a
 * development stack the check is a forced decision (approval Q-23) because the current model asks for none.
 */
test.skip(process.env.SHOWCASE_LIVE_DEV !== '1', 'needs the development single space');

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

const RUN_TIMEOUT = 90_000;

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => violation.id);
}

async function startRun(page: Page) {
  await page.goto('/try?lng=en');
  await page.getByRole('button', { name: 'Run', exact: true }).click();
  // The heading, not the lead paragraph that mentions the same words.
  await expect(page.getByRole('heading', { name: 'Contexa asks you to confirm it is you' })).toBeVisible({
    timeout: RUN_TIMEOUT,
  });
}

async function showCode(page: Page) {
  await page.getByRole('button', { name: 'Send me the code' }).click();
  const code = page.getByTestId('inbox-code');
  await expect(code).toBeVisible();
  return (await code.textContent())?.trim() ?? '';
}

test.describe.configure({ mode: 'serial' });

test('the visitor answers the check with the demo inbox code and the work comes back', async ({ page }, info) => {
  test.skip(info.project.name !== 'chromium', 'one live run at a time');
  test.setTimeout(4 * RUN_TIMEOUT);
  await startRun(page);
  expect(await seriousViolations(page)).toEqual([]);
  const code = await showCode(page);
  expect(code).toMatch(/\S{4,}/);
  if (evidenceDir) {
    await page.screenshot({ path: join(evidenceDir, 'try-code-shown.png'), fullPage: true });
  }
  await page.getByRole('button', { name: 'Confirm with this code' }).click();

  await expect(page.getByText('Control and recovery')).toBeVisible({ timeout: RUN_TIMEOUT });
  await expect(page.getByText(/Data delivered · HTTP 200/)).toBeVisible();
  await expect(page.getByText('You confirmed it was you and the work carried on')).toBeVisible({
    timeout: RUN_TIMEOUT,
  });
  expect(await seriousViolations(page)).toEqual([]);
  if (evidenceDir) {
    await page.screenshot({ path: join(evidenceDir, 'try-recovered.png'), fullPage: true });
  }
});

test('a cancelled check stays on hold and can be confirmed again', async ({ page }, info) => {
  test.skip(info.project.name !== 'chromium', 'one live run at a time');
  test.setTimeout(4 * RUN_TIMEOUT);
  await startRun(page);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByText('You cancelled the identity check. The request is on hold.')).toBeVisible();
  if (evidenceDir) {
    await page.screenshot({ path: join(evidenceDir, 'try-cancelled.png'), fullPage: true });
  }
  // Confirming again asks for a new code at once, so the demo inbox shows it without another click.
  await page.getByRole('button', { name: 'Confirm again' }).click();
  const inbox = page.getByTestId('inbox-code');
  await expect(inbox).toBeVisible();
  // Typing the code is the other way in; it goes through the same verification.
  const code = (await inbox.textContent())?.trim() ?? '';
  await page.getByText('Type it instead').click();
  await page.getByLabel('Enter the code').fill(code);
  await page.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByText(/Data delivered · HTTP 200/)).toBeVisible({ timeout: RUN_TIMEOUT });
  await expect(page.getByText('You confirmed it was you and the work carried on')).toBeVisible({
    timeout: RUN_TIMEOUT,
  });
});

test('three wrong codes end the check as a failed recovery with its cause', async ({ page }, info) => {
  test.skip(info.project.name !== 'chromium', 'one live run at a time');
  test.setTimeout(4 * RUN_TIMEOUT);
  await startRun(page);
  await showCode(page);
  await page.getByText('Type it instead').click();
  for (const attempt of [1, 2]) {
    await page.getByLabel('Enter the code').fill(`wrong-${attempt}`);
    await page.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect(page.getByText(`That code does not match (${attempt}/3)`)).toBeVisible();
  }
  await page.getByLabel('Enter the code').fill('wrong-3');
  await page.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByText('The work could not continue.')).toBeVisible({ timeout: RUN_TIMEOUT });
  await page.getByText('See the cause').click();
  await expect(page.getByText('The code was entered wrongly three times.')).toBeVisible();
  if (evidenceDir) {
    await page.screenshot({ path: join(evidenceDir, 'try-recovery-failed.png'), fullPage: true });
  }
});
