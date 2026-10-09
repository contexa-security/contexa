import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * The stepped lab on the real portal (screen design v2.3, 7.6): the entrance, picking a case, changing one condition,
 * the comparison before sending, predicting and sending, the result compared with the previous run and the
 * assessment, and the rule tightening. The visitor sends the real employee's approved export (A3T) as designed, then
 * again with the approval taken away, so the second result is compared with the first. Every value on screen is
 * checked against the portal's own answer.
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
const RUN_TIMEOUT = 240_000;
const CASE = 'A3T';

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

function format(template: string, values: Readonly<Record<string, string | number>>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? ''));
}

const api = (page: Page, path: string) =>
  page.evaluate((target) => fetch(target).then((r) => (r.ok ? r.json() : null)), path);

/** A POST the way the app sends it: with the CSRF token of the cookie in its header. */
const post = (page: Page, path: string, body: unknown) =>
  page.evaluate(
    ([target, payload]) => {
      const token = /(?:^|; )XSRF-TOKEN=([^;]*)/.exec(document.cookie)?.[1];
      return fetch(target as string, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'X-XSRF-TOKEN': decodeURIComponent(token) } : {}),
        },
        body: JSON.stringify(payload),
      }).then((r) => r.json());
    },
    [path, body] as const,
  );

/** Predicts, sends and waits for the result link of the lab run on the send step. */
async function sendAndWait(page: Page, m: Record<string, string>, call: 'NORMAL' | 'ATTACK') {
  await page.getByLabel(m[`labSend.calls.${call}`] ?? '', { exact: true }).check();
  await page.getByRole('button', { name: m['labSend.send'] ?? '' }).click();
  await page.waitForURL(/sent=/);
  await page.getByRole('link', { name: m['labSend.toResult'] ?? '' }).waitFor({ timeout: RUN_TIMEOUT });
  await page.getByRole('link', { name: m['labSend.toResult'] ?? '' }).click();
  await page.waitForURL(/\/lab\/result\?run=/);
}

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`the lab sends a changed case and compares it with the previous run (${language})`, async ({
    page,
  }) => {
    test.setTimeout(2 * RUN_TIMEOUT + 180_000);

    // L0: the entrance with the runs left today, as the portal counts them.
    await page.goto(`/lab?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['labEntrance.title'] ?? '');
    const config = await api(page, '/api/live/config');
    await expect(page.locator('main')).toContainText(
      format(m['labEntrance.remaining'] ?? '', { n: config.remainingToday }),
    );
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole('link', { name: m['labEntrance.next'] ?? '' }).click();

    // L1: the filter, the case cards with the case definition's answer and the benchmark's count.
    await page.waitForURL(/\/lab\/case/);
    await page.getByRole('button', { name: m['labCase.filters.normal'] ?? '' }).click();
    const options = await api(page, '/api/lab/options');
    const a3t = options.cases.find((candidate: { key: string }) => candidate.key === CASE);
    // The designed case's own title, not its asynchronous or stream variants (their titles add a bracket).
    const title = (a3t.title[language] as string).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const card = page.getByRole('button', { name: new RegExp(`· ${title}(?!\\s*\\()`) });
    await card.click();
    await expect(card).toHaveAttribute('aria-pressed', 'true');
    await expect(card).toContainText(m['labCase.answer.pass'] ?? '');
    const benchmark = await api(page, '/api/benchmark');
    const cell = benchmark.cases.find((entry: { key: string }) => entry.key === CASE)?.cells?.D;
    if (cell && cell.counted > 0) {
      await expect(card).toContainText(
        format(m['labCase.contexa'] ?? '', { k: cell.right, n: cell.counted }),
      );
    }
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole('link', { name: m['labCase.next'] ?? '' }).click();

    // L2 as designed, L2-2, L2-3: the first run is the case as designed.
    await page.waitForURL(/\/lab\/change\?case=A3T/);
    await page.getByRole('link', { name: m['labChange.next'] ?? '' }).click();
    await page.waitForURL(/\/lab\/before\?case=A3T$/);
    await expect(page.locator('main')).toContainText(m['labBefore.answer.pass'] ?? '');
    await page.getByRole('link', { name: m['labBefore.next'] ?? '' }).click();
    await page.waitForURL(/\/lab\/send\?case=A3T$/);
    await sendAndWait(page, m, 'NORMAL');
    await expect(page.locator('main')).toContainText(m['labResult.purposeOnly'] ?? '');
    const first = new URL(page.url()).searchParams.get('run');

    // L2 with one change: the approval record, in the address.
    await page.getByRole('link', { name: m['labResult.next'] ?? '' }).click();
    await page.waitForURL(/\/lab\/change\?case=A3T/);
    await page.getByRole('button', { name: m['lab.field.approval'] ?? '', exact: true }).click();
    await page
      .getByLabel(format(m['labChange.newValue'] ?? '', { name: m['lab.field.approval'] ?? '' }), {
        exact: true,
      })
      .selectOption('false');
    await page.waitForURL(/approval=false/);
    await expect(page.locator('main details')).toContainText(m['labChange.advanced'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole('link', { name: m['labChange.next'] ?? '' }).click();

    // L2-2: the changed case's comparison is the portal's (or says there is none yet), with no answer set in advance.
    await page.waitForURL(/\/lab\/before\?case=A3T&approval=false/);
    const before = await post(page, '/api/lab/before', {
      caseKey: CASE,
      conditions: { approval: false },
      step: 1,
    });
    if (before.comparison === null) {
      await expect(page.locator('main')).toContainText(m['labBefore.noRecord'] ?? '');
    } else {
      await expect(page.locator('section[aria-labelledby="before-usual"]')).toContainText(
        String(before.comparison.departureCount),
      );
    }
    await expect(page.locator('main')).toContainText(m['labBefore.noAnswer'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole('link', { name: m['labBefore.next'] ?? '' }).click();

    // L2-3 and L3: the second run against the first, compared by the server.
    await page.waitForURL(/\/lab\/send\?case=A3T&approval=false/);
    await sendAndWait(page, m, 'ATTACK');
    const url = new URL(page.url());
    expect(url.searchParams.get('against')).toBe(first);
    const versus = await api(page, `/api/runs/${url.searchParams.get('run')}/versus?against=${first}`);
    const verdict = (action: string | null) =>
      m[
        {
          ALLOW: 'verdict.allow',
          CHALLENGE: 'verdict.verify',
          ESCALATE: 'verdict.review',
          BLOCK: 'verdict.block',
        }[action ?? ''] ?? 'verdict.none'
      ] ?? '';
    // The headline names the changed conditions as the server compared the two runs (plan 7.0, lab-3).
    const verdicts = { from: verdict(versus.before.engineAction), to: verdict(versus.now.engineAction) };
    const conditions: readonly string[] | null = versus.changedConditions;
    const changedHeadline =
      conditions === null
        ? format(m['labResult.changed'] ?? '', verdicts)
        : conditions.length === 0
          ? format(m['labResult.changedSame'] ?? '', verdicts)
          : conditions.length === 1
            ? format(m['labResult.changedOne'] ?? '', {
                ...verdicts,
                condition: m[`lab.fieldInline.${conditions[0]}`] ?? '',
              })
            : format(m['labResult.changedMany'] ?? '', { ...verdicts, n: conditions.length });
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      versus.contexaChanged
        ? changedHeadline
        : format(m['labResult.same'] ?? '', { verdict: verdict(versus.now.engineAction) }),
    );
    await expect(page.locator('main table tbody tr[data-changed]')).toHaveCount(
      versus.changedControls.length,
    );
    await expect(page.locator('main')).toContainText(m['labSend.calls.ATTACK'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);

    // S9-05: the run's decision details open over the lab result; the browser's back button closes them.
    const labAddress = page.url();
    await page.getByRole('button', { name: m['labResult.detail'] ?? '' }).click();
    await expect(page).toHaveURL(new RegExp(`detailRun=${url.searchParams.get('run')}`));
    await expect(page.getByRole('dialog').getByRole('tab')).toHaveCount(6);
    await page.goBack();
    await expect(page.getByRole('dialog')).toBeHidden();
    expect(page.url()).toBe(labAddress);

    // The assessment opens in a window and is stored once.
    await page.getByRole('button', { name: m['labResult.assess'] ?? '' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');

    // R: the two counts and Contexa's recorded counts are the server's, and a changed setting is decided again.
    await page.goto(`/lab/rules?lng=${language}`);
    const cases = await api(page, '/api/rules/cases');
    const evaluate = (settings: unknown) => post(page, '/api/rules/evaluate', settings);
    const published = await evaluate(cases.defaults.settings);
    const counts = page.locator('main dl dd');
    await expect(counts.nth(0)).toHaveText(
      format(m['labRules.ofTotal'] ?? '', {
        k: published.tallies.C1.attacksStopped,
        n: published.tallies.C1.attacks,
      }),
    );
    await expect(page.locator('main')).toContainText(
      format(m['labRules.contexa'] ?? '', {
        k: published.tallies.D.attacksStopped,
        n: published.tallies.D.attacks,
        m: published.tallies.D.normalsBlocked,
        p: published.tallies.D.normals,
        c: published.tallies.D.normalsChecked,
      }),
    );
    await page.getByLabel(m['labRules.nightStart'] ?? '').selectOption('2');
    const tightened = await evaluate({ ...cases.defaults.settings, nightStartHour: 2 });
    await expect(counts.nth(0)).toHaveText(
      format(m['labRules.ofTotal'] ?? '', {
        k: tightened.tallies.C1.attacksStopped,
        n: tightened.tallies.C1.attacks,
      }),
    );
    await page.getByRole('tab', { name: m['labRules.tab.c2'] ?? '' }).click();
    await expect(page).toHaveURL(/tab=c2/);
    expect(await seriousViolations(page)).toEqual([]);
  });
}
