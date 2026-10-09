import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * The concept path on the real portal (screen design v2.3, 7.5, D-33, D-37): the introduction with its three ways, the
 * problem drawn in two layers, how we compare with what the runs share, the order of the tries, and the nine-step band
 * on the screens both routes share. The route comes from the address, then from a screen only one route lists, then
 * from the stored journey; a shared address keeps ?route=intro. No run is sent.
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

function items(value: number, language: 'ko' | 'en'): string {
  return value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US');
}

const api = (page: Page, path: string) =>
  page.evaluate((target) => fetch(target).then((r) => (r.ok ? r.json() : null)), path);

/** The place band: the concept path draws one tab and nine steps, the default route four act tabs. */
async function band(page: Page) {
  const lists = page.locator('main nav ol');
  return {
    tabs: await lists.nth(0).locator(':scope > li').count(),
    steps: await lists.nth(1).locator(':scope > li').count(),
  };
}

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`the concept path keeps its route and shows the case values (${language})`, async ({ page }) => {
    // G1 opened from the menu's address without ?route=: a screen only the concept path lists is on that path.
    await page.goto(`/intro?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['intro.title'] ?? '');
    await expect.poll(() => band(page)).toEqual({ tabs: 1, steps: 9 });
    await expect(page.locator('main')).toContainText(m['identity.definition'] ?? '');
    await expect(
      page.getByRole('list', { name: m['intro.differences'] ?? '' }).getByRole('listitem'),
    ).toHaveCount(6);
    await expect(page.getByRole('link', { name: m['intro.try'] ?? '' })).toHaveAttribute(
      'href',
      '/try/attacker/scene?route=default',
    );
    expect(await seriousViolations(page)).toEqual([]);

    // G2: layer 1, then "next" draws layer 2 over it at its own address; the count is try 1's case definition.
    await page.getByRole('link', { name: m['intro.next'] ?? '' }).click();
    await page.waitForURL(/\/intro\/concept\?route=intro/);
    const options = await api(page, '/api/lab/options');
    const a3 = options.cases.find((candidate: { key: string }) => candidate.key === 'A3');
    await expect(page.locator('main figure')).toContainText(
      format(m['concept.export'] ?? '', { items: items(a3.requests[0].items, language) }),
    );
    await expect(page.getByText(m['concept.conclusion'] ?? '')).toHaveCount(0);
    await page.getByRole('link', { name: m['concept.reveal'] ?? '', exact: true }).click();
    await page.waitForURL(/layer=2/);
    await expect(page.getByText(m['concept.conclusion'] ?? '')).toBeVisible();
    await page.reload();
    await expect(page.getByText(m['concept.conclusion'] ?? '')).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    // On to G3, a screen both routes share: on the concept path it shows the nine steps.
    await page.getByRole('link', { name: m['concept.nextJudge'] ?? '' }).click();
    await page.waitForURL(/\/intro\/approaches\?route=intro/);
    await expect.poll(() => band(page)).toEqual({ tabs: 1, steps: 9 });

    // G4: five lanes, three results, and what the runs share from the record and the published settings.
    await page.goto(`/intro/compare?lng=${language}`);
    await expect(page.locator('main figure ol > li')).toHaveCount(5);
    await page.getByRole('button', { name: m['compare.same'] ?? '' }).click();
    const dialog = page.getByRole('dialog');
    const settings = await api(page, '/api/settings');
    const benchmark = await api(page, '/api/benchmark');
    await expect(dialog).toContainText(
      format(m['compare.env.C1'] ?? '', {
        from: settings.threshold.nightStart,
        to: settings.threshold.nightEnd,
        n: items(settings.threshold.volumeLimit, language),
      }),
    );
    await expect(dialog).toContainText(benchmark.spec.codeCommit.slice(0, 8));
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press('Escape');

    // G5: the try cards from the case definitions; the main button starts try 1 on the concept path.
    await page.goto(`/intro/order?lng=${language}`);
    const employee = options.employees.find(
      (candidate: { key: string }) => candidate.key === a3.conditions.employee,
    );
    const slot = options.timeSlots.find(
      (candidate: { slot: string }) => candidate.slot === a3.conditions.timeSlot,
    );
    await expect(page.locator('main')).toContainText(
      format(m['order.try1.what'] ?? '', {
        name: employee.displayName,
        when: format(m[`lab.slot.${slot.slot}`] ?? '', { time: slot.representativeTime }),
        project: a3.requests[0].project,
        items: items(a3.requests[0].items, language),
      }),
    );
    const a6t = options.cases.find((candidate: { key: string }) => candidate.key === 'A6T');
    await expect(page.locator('main')).toContainText(
      format(m['order.try3.what'] ?? '', { steps: a6t.requests.length }),
    );
    expect(await seriousViolations(page)).toEqual([]);
    await page.getByRole('link', { name: m['order.next'] ?? '' }).click();
    await page.waitForURL(/\/try\/attacker\/scene\?route=intro/);
    await expect.poll(() => band(page)).toEqual({ tabs: 1, steps: 9 });
  });

  test(`a shared address keeps the route and the introduction leads into the default route (${language})`, async ({
    page,
  }) => {
    // A concept-path address opened in a new visitor's browser keeps the concept path.
    await page.goto(`/intro/how?route=intro&lng=${language}`);
    await expect.poll(() => band(page)).toEqual({ tabs: 1, steps: 9 });
    // The same screen on the default route shows the four acts.
    await page.goto(`/intro/how?route=default&lng=${language}`);
    await expect.poll(async () => (await band(page)).tabs).toBe(4);
    // "Try it yourself now" from the introduction starts try 1 on the default route.
    await page.goto(`/intro?lng=${language}`);
    await page.getByRole('link', { name: m['intro.try'] ?? '' }).click();
    await page.waitForURL(/\/try\/attacker\/scene\?route=default/);
    await expect.poll(async () => (await band(page)).tabs).toBe(4);
  });
}
