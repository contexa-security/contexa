import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * Act 1 on the real portal (screen design v2.3, 7.1): the first screen replays the designated measured runs, and try
 * 1 sends one real export through the visitor's own gate and shows it in seven steps and the act-end screen (D-41). Every value
 * on screen is checked against the portal's own answer for the same run. It needs a portal with live runs of A3 on and
 * limits high enough for one run per language.
 */
const MESSAGES = {
  ko: JSON.parse(readFileSync(new URL('../../src/i18n/ko.json', import.meta.url), 'utf-8')) as Record<
    string,
    string
  >,
  en: JSON.parse(readFileSync(new URL('../../src/i18n/en.json', import.meta.url), 'utf-8')) as Record<
    string,
    string
  >,
};
const RUN_TIMEOUT = 180_000;
const CONTROLS = ['A', 'B', 'C1', 'C2', 'D'] as const;

interface HookLayer {
  readonly control: string;
  readonly outcome: string;
  readonly verdict: string | null;
  readonly evidence: { readonly deliveredItems: number };
}

interface HookColumn {
  readonly runId: string;
  readonly correct: Readonly<Record<string, boolean>>;
  readonly result: { readonly layers: readonly HookLayer[] };
  readonly measurement: {
    readonly runs: number;
    readonly sameResult: number;
    readonly passedAfterCheck: number;
  };
}

interface RunScore {
  readonly business: Readonly<Record<string, { readonly result: string; readonly exposedItems: number }>>;
  readonly correct: Readonly<Record<string, boolean>>;
}

test.describe.configure({ mode: 'serial' });

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map(
      (violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(' ')).join(', ')}`,
    );
}

async function noHorizontalScroll(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

function format(template: string, values: Readonly<Record<string, string | number>>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? ''));
}

function items(value: number, language: 'ko' | 'en'): string {
  return value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US');
}

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`the first screen replays the designated measured runs as recorded (${language})`, async ({
    page,
  }) => {
    await page.goto(`/?lng=${language}`);
    const hook = await page.evaluate(() => fetch('/api/hook').then((r) => (r.ok ? r.json() : null)));
    test.skip(hook === null, 'no designated runs on this portal');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.reload();
    for (const side of ['attacker', 'owner'] as const) {
      const column = hook[side] as HookColumn;
      const contexa = column.result.layers.find((layer) => layer.control === 'D');
      expect(contexa, side).toBeTruthy();
      const row = page.locator(`[data-side="${side}"] [data-contexa]`);
      await expect(row).toContainText(items(contexa?.evidence.deliveredItems ?? -1, language));
      const measured = column.measurement;
      const line =
        side === 'owner' && measured.passedAfterCheck > 0
          ? format(m['hook.measuredAfterCheck'] ?? '', { runs: measured.runs, n: measured.passedAfterCheck })
          : measured.sameResult === measured.runs
            ? format(m['hook.measuredSame'] ?? '', { runs: measured.runs })
            : format(m['hook.measuredSome'] ?? '', { runs: measured.runs, same: measured.sameResult });
      await expect(page.locator(`[data-side="${side}"]`)).toContainText(line);
      await expect(page.locator(`[data-side="${side}"]`)).toContainText(
        m[side === 'attacker' ? 'hook.answer.stop' : 'hook.answer.pass'] ?? '',
      );
      // Contexa's row carries the server's score as a word next to its icon.
      await expect(row).toContainText(m[column.correct['D'] ? 'mark.right' : 'mark.wrong'] ?? '');
    }
    await expect(
      page.getByText(m[hook.distinguished ? 'hook.question' : 'hook.questionFallback'] ?? ''),
    ).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });

  test(`try 1 sends one live run and every step shows its records (${language})`, async ({ page }) => {
    test.setTimeout(RUN_TIMEOUT + 120_000);
    await page.goto(`/try/attacker/scene?lng=${language}`);
    const options = await page.evaluate(() => fetch('/api/lab/options').then((r) => r.json()));
    const a3 = options.cases.find((candidate: { key: string }) => candidate.key === 'A3');
    const employee = options.employees.find(
      (candidate: { key: string }) => candidate.key === a3.conditions.employee,
    );
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      format(m['e1.scene.title'] ?? '', { name: employee.displayName }),
    );

    await page.goto(`/try/attacker/compare?lng=${language}`);
    const before = await page.evaluate(() => fetch('/api/live/before/A3?step=1').then((r) => r.json()));
    if (before.comparison) {
      await expect(page.getByRole('heading', { level: 1 })).toHaveText(
        format(m['e1.compare.title'] ?? '', {
          usual: before.comparison.departureCount,
          company: before.comparison.companyAdverseCount,
        }),
      );
    }

    await page.goto(`/try/attacker/predict?lng=${language}`);
    await page
      .getByText(m['e1.predict.CHALLENGE'] ?? '', { exact: true })
      .first()
      .click();
    await page.getByText(m['e1.predict.existing.SOME'] ?? '', { exact: true }).click();
    await page
      .getByRole('button', {
        name: format(m['e1.predict.send'] ?? '', { items: items(a3.requests[0].items, language) }),
      })
      .click();
    await page.waitForURL(/\/try\/attacker\/run/);
    await page.getByRole('link', { name: m['e1.next.result'] ?? '' }).waitFor({ timeout: RUN_TIMEOUT });
    expect(await seriousViolations(page)).toEqual([]);

    const live = await page.evaluate(() => fetch('/api/live/runs/current').then((r) => r.json()));
    const score = (await page.evaluate(
      (runId) => fetch(`/api/runs/${runId}/score`).then((r) => r.json()),
      live.runId,
    )) as RunScore;
    await page.goto(`/try/attacker/result?lng=${language}`);
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(CONTROLS.length);
    for (const [index, control] of CONTROLS.entries()) {
      const right = score.correct[control];
      const mark = right === undefined ? m['mark.neither'] : right ? m['mark.right'] : m['mark.wrong'];
      await expect(rows.nth(index)).toContainText(mark ?? '');
      await expect(rows.nth(index)).toContainText(
        format(m['e1.result.items'] ?? '', {
          items: items(score.business[control]?.exposedItems ?? -1, language),
        }),
      );
    }
    const journey = await page.evaluate(() => fetch('/api/journey').then((r) => r.json()));
    const call = journey.predictions.find((prediction: { caseKey: string }) => prediction.caseKey === 'A3');
    expect(call?.call.engine).toBe('CHALLENGE');
    // S9-05: the run's decision details open over the result and close back to it, the focus on their button.
    const resultAddress = page.url();
    const openDetail = page.getByRole('button', { name: m['e1.result.detail'] ?? '' });
    await openDetail.click();
    await expect(page).toHaveURL(new RegExp(`detailRun=${live.runId}&detailStep=1`));
    await expect(page.getByRole('dialog').getByRole('tab')).toHaveCount(6);
    await page
      .getByRole('dialog')
      .getByRole('button', { name: m['modal.close'] ?? '' })
      .click();
    await expect(page.getByRole('dialog')).toBeHidden();
    expect(page.url()).toBe(resultAddress);
    await expect(openDetail).toBeFocused();

    await page.goto(`/try/attacker/reason?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    // Difference 4 counts as seen once the reasons are drawn; leave only after the server has it.
    await expect
      .poll(
        async () =>
          (await page.evaluate(() => fetch('/api/journey').then((r) => r.json()))).state.differences,
      )
      .toContain(4);
    // S9-05: from the reasons too; Esc closes the details and leaves the reasons.
    const reasonAddress = page.url();
    await page.getByRole('button', { name: m['e1.result.detail'] ?? '' }).click();
    await expect(page).toHaveURL(new RegExp(`detailRun=${live.runId}`));
    await expect(page.getByRole('dialog').getByRole('tab')).toHaveCount(6);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toBeHidden();
    expect(page.url()).toBe(reasonAddress);
    await page.goto(`/try/attacker/after?lng=${language}`);
    const ended = await page.evaluate(() => fetch('/api/live/runs/current').then((r) => r.json()));
    if (ended.challenge) {
      expect(ended.challenge.stage).toBe('NO_MAILBOX');
      await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['e1.after.title'] ?? '');
    }
    await expect(
      page.getByRole('button', { name: format(m['difference.badgeAria'] ?? '', { n: 4 }) }),
    ).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    // The act-end card is a screen of its own, opened by the follow-up's one next button (D-41).
    await page.getByRole('link', { name: m['e1.next.end'] ?? '' }).click();
    await page.waitForURL(/\/try\/attacker\/end/);
    await expect(page.locator('section[aria-labelledby="act-end-1"]')).toBeVisible();
    // The act-end screen's one main button starts act 2, and its way back is the follow-up.
    await expect(page.getByRole('link', { name: format(m['actEnd.start'] ?? '', { n: 2 }) })).toHaveAttribute(
      'href',
      '/try/owner/scene',
    );
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });
}
