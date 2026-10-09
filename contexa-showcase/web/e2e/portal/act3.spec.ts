import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * Act 3 on the real portal (screen design v2.3, 7.3): prior learning, how it judges, the prompt, the two decision
 * modes with the visitor's attack sent again asynchronously, try 3 sent live, learning after a decision and the act-end
 * screen. Every value on screen is checked against the portal's own answer. It needs a portal with live runs of A3A and
 * A6T on and limits high enough for two runs per language.
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

function seconds(ms: number): string {
  return ms >= 1000 ? (ms / 1000).toFixed(1) : (ms / 1000).toFixed(2);
}

const api = (page: Page, path: string) =>
  page.evaluate((target) => fetch(target).then((r) => (r.ok ? r.json() : null)), path);

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`act 3 shows the records and runs try 3 and the asynchronous resend live (${language})`, async ({
    page,
  }) => {
    test.setTimeout(2 * RUN_TIMEOUT + 240_000);

    // Prior learning 1: the learned hours of try 1's employee with the request's hour marked.
    await page.goto(`/intro/learning?lng=${language}`);
    const options = await api(page, '/api/lab/options');
    const a3 = options.cases.find((candidate: { key: string }) => candidate.key === 'A3');
    const slot = options.timeSlots.find(
      (candidate: { slot: string }) => candidate.slot === a3.conditions.timeSlot,
    );
    const when = format(m[`lab.slot.${slot.slot}`] ?? '', { time: slot.representativeTime });
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      format(m['learnWhy.title'] ?? '', { when }),
    );
    const baseline = await api(page, `/api/live/baseline/${a3.conditions.employee}`);
    const hour = Number(slot.representativeTime.slice(0, 2));
    if (baseline.learned.hours[hour] === 0) {
      await expect(page.locator('main')).toContainText(
        format(m['learnWhy.known.zero'] ?? '', { n: items(baseline.learned.requests, language), hour }),
      );
    }
    expect(await seriousViolations(page)).toEqual([]);

    // Prior learning 2: the engine's own learning states and the learned requests.
    await page.goto(`/intro/learning/learned?lng=${language}`);
    await expect(
      page.getByText(m[`learned.state.${baseline.hours.personalBaselineStatus}`] ?? ''),
    ).toBeVisible();
    await expect(page.getByText(m[`learned.state.${baseline.hours.roleScopeState}`] ?? '')).toBeVisible();
    await page
      .getByRole('button', { name: format(m['learned.requestsOpen'] ?? '', { n: baseline.sent }) })
      .click();
    await expect(page.locator('dialog table tbody tr')).toHaveCount(baseline.sent);
    await page.keyboard.press('Escape');
    expect(await seriousViolations(page)).toEqual([]);

    // How it judges: nine cells, each saying what it does when pressed.
    await page.goto(`/intro/how?lng=${language}`);
    await expect(page.locator('main ol button')).toHaveCount(9);
    await page.getByRole('button', { name: new RegExp(m['inside.cell.company'] ?? '') }).click();
    await expect(page.getByText(m['how.cell.company'] ?? '')).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    // The prompt: every bundle's line count is the server's.
    await page.goto(`/try/prompt?lng=${language}`);
    const journey = await api(page, '/api/journey');
    const own = [...journey.runs]
      .reverse()
      .find(
        (line: { scenarioKey: string; status: string }) =>
          line.scenarioKey === 'A3' && line.status === 'COMPLETED',
      );
    const teasers = await api(page, '/api/teasers');
    const promptRun =
      own?.runId ??
      teasers.teasers.find((teaser: { key: string }) => teaser.key === 'G_HOW_LINES').source.ref;
    const anatomy = await api(page, `/api/runs/${promptRun}/steps/1/anatomy`);
    for (const bundle of ['RULES', 'COMPANY']) {
      const lines = anatomy.promptLines.bundles.find(
        (entry: { bundle: string }) => entry.bundle === bundle,
      ).lines;
      await expect(
        page.getByRole('button', { name: new RegExp(m[`prompt.bundle.${bundle}`] ?? '') }),
      ).toContainText(format(m['prompt.lines'] ?? '', { n: items(lines, language) }));
    }
    await expect(page.getByText(m['prompt.plain.approvalRequired'] ?? '')).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    // T1: the measured middle run of each mode.
    await page.goto(`/try/timing/concept?lng=${language}`);
    const sync = await api(page, '/api/cases/A3/measured');
    const syncRun = sync.list.find((run: { runId: string }) => run.runId === sync.middleRun);
    await expect(page.locator('main')).toContainText(
      format(m['timing.concept.sync'] ?? '', {
        seconds: seconds(syncRun.responseMs),
        items: items(syncRun.exposedItems, language),
      }),
    );
    expect(await seriousViolations(page)).toEqual([]);

    // T2: the visitor sends the same attack asynchronously; the run step brings them back here.
    await page.goto(`/try/timing/try?lng=${language}`);
    await page.getByRole('button', { name: m['timing.try.send'] ?? '' }).click();
    await page.waitForURL(/\/try\/attacker\/run\?mode=async&from=timing/);
    // The asynchronous attack has a second request the visitor sends, the one the earlier decision refuses.
    const back = page.getByRole('link', { name: m['timing.try.backToResend'] ?? '' });
    const deadline = Date.now() + RUN_TIMEOUT;
    while (Date.now() < deadline && !(await back.count())) {
      const next = page.getByRole('button', { name: new RegExp(m['e1.run.sendNext']?.split('{{')[0] ?? '') });
      if (await next.count()) {
        await next.first().click();
      }
      await page.waitForTimeout(1000);
    }
    await page.getByRole('link', { name: m['timing.try.backToResend'] ?? '' }).click();
    await page.waitForURL(/\/try\/timing\/try/);
    const resent = await api(page, '/api/live/runs/current');
    const resentResult = await api(page, `/api/runs/${resent.runId}/steps/1/result`);
    const delivered = resentResult.layers.find((layer: { control: string }) => layer.control === 'D').evidence
      .deliveredItems;
    await expect(page.locator('main')).toContainText(
      format(m['timing.items'] ?? '', { items: items(delivered, language) }),
    );
    expect(await seriousViolations(page)).toEqual([]);

    // T3 and T4: the server's ranges.
    await page.goto(`/try/timing/compare?lng=${language}`);
    await expect(page.locator('table tbody tr')).toHaveCount(2);
    await page.goto(`/try/timing/when?lng=${language}`);
    await expect(page.getByText(m['timing.when.q1'] ?? '')).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    // Try 3: sent live; the meter fills from the stored anatomies of its five requests.
    await page.goto(`/try/stack?lng=${language}`);
    await page.getByRole('button', { name: m['stack.send'] ?? '' }).click();
    await expect(page.locator('main table tbody tr')).toHaveCount(5, { timeout: RUN_TIMEOUT });
    // Difference 6 counts as seen once the visitor's own try 3 is on screen (thread, C-9).
    await expect
      .poll(async () => (await api(page, '/api/journey')).state.differences as number[])
      .toContain(6);
    const stack = await api(page, '/api/live/runs/current');
    const last = await api(page, `/api/runs/${stack.runId}/steps/5/anatomy`);
    await expect(page.locator('main')).toContainText(
      `${last.figures.baselineBefore} → ${last.figures.baselineAfter}`,
    );
    expect(await seriousViolations(page)).toEqual([]);

    // Learning after a decision, then the end of act 3 with the visitor's own learning sentence.
    await page.goto(`/try/summary/learning?lng=${language}`);
    await expect(page.getByText(m['learnAfter.rule.stopped'] ?? '')).toBeVisible();
    await page.getByRole('link', { name: m['learnAfter.next'] ?? '' }).click();
    await page.waitForURL(/\/try\/summary\/learning\/end/);
    await expect(page.locator('section[aria-labelledby="act-end-3"]')).toBeVisible();
    const actEnd = await api(page, '/api/journey/act-end?act=3');
    if (actEnd.values.from !== actEnd.values.to) {
      await expect(page.locator('main')).toContainText(
        format(m['actEnd.3.grew'] ?? '', { from: actEnd.values.from, to: actEnd.values.to }),
      );
    }
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });
}
