import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The final screen design (최종화면-구현계획 F0-1) replaced the flow this spec walks; mainFlow.spec.ts and
// keyboard.spec.ts walk the new one. This spec is on the deletion list for the user (최종화면-구현계획 4절).
test.skip(true, 'replaced by mainFlow.spec.ts (최종화면-구현계획 FC-2)');

/**
 * The start, part 1 and part 2 on the real portal (docs/showcase/화면재편-구현계획.md R2-R3, RC-6): the start shows the
 * designated measured runs as recorded, try 1 and try 2 each send one real export through the visitor's own gate and
 * walk it screen by screen with the one main button, from the cover to the part's wrap-up. Every value on screen is
 * checked against the portal's own answer. It needs a portal with live runs of A3 and A3T on and limits high enough
 * for two runs per language, and no other runs going (2-6 compares the demo-wide counts).
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
  readonly verdict: string | null;
  readonly evidence: { readonly deliveredItems: number };
}

interface HookColumn {
  readonly runId: string;
  readonly result: { readonly layers: readonly HookLayer[] };
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

/** The bottom bar's one main button; every screen of the flow has exactly one. */
function mainButton(page: Page) {
  return page.locator('[data-zone="actions"] [data-main]');
}

/** Presses the main button, checks it says the next screen's question (RC-3) and waits for that screen. */
async function next(page: Page, words: string, path: RegExp) {
  const button = mainButton(page);
  await expect(button).toHaveCount(1);
  await expect(button).toHaveText(words);
  await button.click();
  await page.waitForURL(path);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

/** The first screen of each part, where its briefing's "start the test" leads. */
const PART_COVERS = [
  '/try/attacker/scene',
  '/try/owner/scene',
  '/intro/learning',
  '/try/timing/concept',
  '/intro/approaches',
];

/**
 * A part's briefing (T0, 화면재편-기획안 15절): the question, the kind of screen and the four short lines, no source
 * line, no horizontal scroll and no serious violation; "skip this part" leads to the next briefing. Then it presses
 * "start the test", which leads to the part's first screen.
 */
async function briefing(page: Page, m: Readonly<Record<string, string>>, part: number) {
  await expect(page).toHaveURL(new RegExp(`/part/${part}`));
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(m[`screen.${part}.title`] ?? '');
  await expect(page.locator('[data-zone="title"] [data-guide]')).toHaveText(m[`screen.${part}.guide`] ?? '');
  const lines = page.locator('[data-zone="body"] > div');
  await expect(lines).toHaveCount(4);
  for (const [index, line] of ['do', 'check', 'try', 'learn'].entries()) {
    await expect(lines.nth(index)).toContainText(m[`brief.label.${line}`] ?? '');
    await expect(lines.nth(index)).toContainText(m[`brief.${part}.${line}`] ?? '');
  }
  await expect(page.locator('[data-zone="source"]')).toHaveCount(0);
  const skip = page.locator('[data-zone="actions"]').getByRole('link', { name: m['frame.skipPart'] ?? '' });
  await expect(skip).toHaveCount(part < 5 ? 1 : 0);
  if (part < 5) {
    await expect(skip).toHaveAttribute('href', `/part/${part + 1}`);
  }
  expect(await seriousViolations(page)).toEqual([]);
  expect(await noHorizontalScroll(page)).toBe(true);
  await next(page, m[`screen.${part}.next`] ?? '', new RegExp(PART_COVERS[part - 1] ?? ''));
}

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`the start shows the designated measured runs as recorded (${language})`, async ({ page }) => {
    await page.goto(`/?lng=${language}`);
    const hook = await page.evaluate(() => fetch('/api/hook').then((r) => (r.ok ? r.json() : null)));
    test.skip(hook === null, 'no designated runs on this portal');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.0.title'] ?? '');
    await expect(
      page.getByText(m[hook.distinguished ? 'screen.0.guide' : 'p0.guide.fallback'] ?? '', { exact: true }),
    ).toBeVisible();
    for (const side of ['attacker', 'owner'] as const) {
      const column = hook[side] as HookColumn;
      const contexa = column.result.layers.find((layer) => layer.control === 'D');
      expect(contexa, side).toBeTruthy();
      const person = page.getByRole('region', { name: m[`p0.${side}.name`] ?? '' });
      await expect(person).toContainText(
        format(m['p0.items'] ?? '', { n: items(contexa?.evidence.deliveredItems ?? -1, language) }),
      );
    }
    // The source line opens the representative run the numbers come from.
    await page
      .locator('[data-zone="source"]')
      .getByRole('button', { name: m['frame.source.open'] ?? '' })
      .click();
    await expect(page).toHaveURL(new RegExp(`detailRun=${(hook.attacker as HookColumn).runId}`));
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(mainButton(page)).toHaveText(m['screen.0.next'] ?? '');
    await expect(mainButton(page)).toHaveAttribute('href', '/part/1');
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });

  test(`try 1 sends one live run and every screen of part 1 shows its records (${language})`, async ({
    page,
  }) => {
    test.setTimeout(RUN_TIMEOUT + 180_000);
    await page.goto(`/part/1?lng=${language}`);
    await briefing(page, m, 1);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.1-0.title'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.1-0.next'] ?? '', /\/try\/attacker\/compare/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.1-1.title'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.1-1.next'] ?? '', /\/try\/attacker\/predict/);

    // 1-2: the visitor's call, then one real send.
    await page
      .getByText(m['verdict.verify'] ?? '', { exact: true })
      .first()
      .click();
    await page.getByRole('button', { name: m['p1.predict.send'] ?? '' }).click();
    await page.waitForURL(/\/try\/attacker\/run/);
    await page.getByRole('link', { name: m['screen.1-3.next'] ?? '' }).waitFor({ timeout: RUN_TIMEOUT });
    expect(await seriousViolations(page)).toEqual([]);

    const live = await page.evaluate(() => fetch('/api/live/runs/current').then((r) => r.json()));
    const score = (await page.evaluate(
      (runId) => fetch(`/api/runs/${runId}/score`).then((r) => r.json()),
      live.runId,
    )) as RunScore;
    await next(page, m['screen.1-3.next'] ?? '', /\/try\/attacker\/result/);

    // 1-4: one table, every cell the server's score of this run.
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(CONTROLS.length);
    for (const [index, control] of CONTROLS.entries()) {
      await expect(rows.nth(index)).toContainText(
        format(m['e1.result.items'] ?? '', {
          items: items(score.business[control]?.exposedItems ?? -1, language),
        }),
      );
      const wrong = rows.nth(index).locator('[data-wrong]');
      await expect(wrong).toHaveCount(score.correct[control] === false ? 1 : 0);
    }
    const journey = await page.evaluate(() => fetch('/api/journey').then((r) => r.json()));
    const call = journey.predictions.find((prediction: { caseKey: string }) => prediction.caseKey === 'A3');
    expect(call?.call.engine).toBe('CHALLENGE');
    expect(call?.runId).toBe(live.runId);
    // The prediction line is the sentence the server's comparison picked (F-5).
    const mine = call.engineSameAction
      ? 'p1.result.mine.same'
      : call.engineSameStop
        ? 'p1.result.mine.sameStop'
        : 'p1.result.mine.other';
    await expect(page.getByText(m[mine] ?? '', { exact: true })).toBeVisible();
    // A reload comes back to the same result of the same run (RC-7).
    await page.reload();
    await expect(rows).toHaveCount(CONTROLS.length);
    await expect(page.getByText(m[mine] ?? '', { exact: true })).toBeVisible();
    // The run's details open over the result and close back to it, the focus on their button.
    const resultAddress = page.url();
    const openDetail = page.getByRole('button', { name: m['frame.detail'] ?? '' });
    await openDetail.click();
    await expect(page).toHaveURL(new RegExp(`detailRun=${live.runId}&detailStep=1`));
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toBeHidden();
    // Closing goes back in the history, so the address returns a moment after the window hides.
    await expect(page).toHaveURL(resultAddress);
    await expect(openDetail).toBeFocused();
    expect(await seriousViolations(page)).toEqual([]);

    // 1-5: the reasons. Difference 4 counts as seen once they are drawn; go on only after the server has it.
    await next(page, m['screen.1-4.next'] ?? '', /\/try\/attacker\/reason/);
    await expect
      .poll(
        async () =>
          (await page.evaluate(() => fetch('/api/journey').then((r) => r.json()))).state.differences,
      )
      .toContain(4);
    expect(await seriousViolations(page)).toEqual([]);

    // 1-6: what happens after the stop, drawn by the judgment this run got.
    await next(page, m['screen.1-5.next'] ?? '', /\/try\/attacker\/after/);
    const ended = await page.evaluate(() => fetch('/api/live/runs/current').then((r) => r.json()));
    if (ended.challenge) {
      expect(ended.challenge.stage).toBe('NO_MAILBOX');
    }
    expect(await seriousViolations(page)).toEqual([]);

    // 1-7: the part's wrap-up, whose one main button starts part 2 and whose way back is 1-6.
    await next(page, m['screen.1-6.next'] ?? '', /\/try\/attacker\/end/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.1-7.title'] ?? '');
    await expect(mainButton(page)).toHaveAttribute('href', '/part/2');
    await expect(mainButton(page)).toHaveText(m['screen.1-7.next'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });

  test(`try 2 sends one live run and every screen of part 2 shows its records (${language})`, async ({
    page,
  }) => {
    test.setTimeout(RUN_TIMEOUT + 180_000);
    await page.goto(`/part/2?lng=${language}`);
    await briefing(page, m, 2);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.2-0.title'] ?? '');
    await next(page, m['screen.2-0.next'] ?? '', /\/try\/owner\/predict/);
    await page
      .getByText(m['verdict.verify'] ?? '', { exact: true })
      .first()
      .click();
    await page.getByRole('button', { name: m['p1.predict.send'] ?? '' }).click();
    await page.waitForURL(/\/try\/owner\/run/);
    await page.getByRole('link', { name: m['screen.2-2.next'] ?? '' }).waitFor({ timeout: RUN_TIMEOUT });
    const live = await page.evaluate(() => fetch('/api/live/runs/current').then((r) => r.json()));
    const score = (await page.evaluate(
      (runId) => fetch(`/api/runs/${runId}/score`).then((r) => r.json()),
      live.runId,
    )) as RunScore;

    // 2-3: the real employee's column is the server's score of this run.
    await next(page, m['screen.2-2.next'] ?? '', /\/try\/owner\/result/);
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(CONTROLS.length);
    for (const [index, control] of CONTROLS.entries()) {
      const wrong = rows.nth(index).locator('td').nth(1).locator('[data-wrong]');
      await expect(wrong).toHaveCount(score.correct[control] === false ? 1 : 0);
    }
    expect(await seriousViolations(page)).toEqual([]);

    // 2-4, then 2-5: one finished identity check, the visitor's own or another request named so (V-20).
    await next(page, m['screen.2-3.next'] ?? '', /\/try\/owner\/reason/);
    await next(page, m['screen.2-4.next'] ?? '', /\/try\/owner\/after/);
    // The address changes before the new screen replaces the old one; read the guide once 2-5's own title is up.
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.2-5.title'] ?? '');
    const guides = [
      'screen.2-5.guide',
      'p2.check.guide.notAsked',
      'p2.check.guide.unfinished',
      'p2.check.guide.noExample',
    ].map((key) => m[key] ?? '');
    const guide = (await page.locator('[data-zone="title"] [data-guide]').innerText()).trim();
    expect(guides).toContain(guide);
    expect(await seriousViolations(page)).toEqual([]);

    // 2-6: four rows, each hold time and count the portal's own (no other runs going while this runs).
    await next(page, m['screen.2-5.next'] ?? '', /\/try\/follow$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.2-6.title'] ?? '');
    const stats = await page.evaluate(() => fetch('/api/stats').then((r) => r.json()));
    const actions = await page.evaluate(() => fetch('/api/engine/actions').then((r) => r.json()));
    for (const verdict of ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const) {
      const row = page.locator(`li[data-verdict="${verdict}"]`);
      const n = items(stats.engineActions[verdict] ?? 0, language);
      await expect(row).toContainText(
        verdict === 'BLOCK'
          ? format(m['p2.follow.blockCount'] ?? '', {
              n,
              promoted: items(stats.blockedAfterReview ?? 0, language),
            })
          : format(m['p2.follow.count'] ?? '', { n }),
      );
      const ttl = actions[verdict]?.ttlSeconds ?? null;
      await expect(row).toContainText(
        ttl === null
          ? (m['p2.follow.hold.none'] ?? '')
          : ttl % 60 === 0
            ? format(m['p2.follow.hold.minutes'] ?? '', { n: items(ttl / 60, language) })
            : format(m['p2.follow.hold.seconds'] ?? '', { n: items(ttl, language) }),
      );
    }
    expect(await seriousViolations(page)).toEqual([]);

    // 2-7: the part's wrap-up, whose one main button starts part 3.
    await next(page, m['screen.2-6.next'] ?? '', /\/try\/follow\/end/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.2-7.title'] ?? '');
    await expect(mainButton(page)).toHaveAttribute('href', '/part/3');
    await expect(mainButton(page)).toHaveText(m['screen.2-7.next'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });

  test(`part 3 walks from its cover through try 3 to its wrap-up with the portal's records (${language})`, async ({
    page,
  }) => {
    test.setTimeout(RUN_TIMEOUT + 420_000);
    await page.goto(`/part/3?lng=${language}`);
    await briefing(page, m, 3);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.3-0.title'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);

    // 3-1: the learned requests in the body are what the engine learned (F-4), not what was sent.
    await next(page, m['screen.3-0.next'] ?? '', /\/intro\/learning\/learned/);
    const card = await page.evaluate(() => fetch('/api/live/baseline/adm-a').then((r) => r.json()));
    await expect(page.locator('[data-zone="body"]')).toContainText(
      format(m['p3.learned.hours'] ?? '', { n: items(card.learned.requests, language) }),
    );
    expect(await seriousViolations(page)).toEqual([]);

    // 3-2: the nine steps.
    await next(page, m['screen.3-1.next'] ?? '', /\/intro\/how/);
    await expect(
      page.getByRole('list', { name: m['p3.how.figure'] ?? '' }).locator(':scope > li'),
    ).toHaveCount(9);
    expect(await seriousViolations(page)).toEqual([]);

    // 3-3: one real send of try 3; the main button is the send button until the run is done.
    await next(page, m['screen.3-2.next'] ?? '', /\/try\/stack/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.3-3.title'] ?? '');
    await page.getByRole('button', { name: m['p3.stack.send'] ?? '' }).click();
    await page
      .getByRole('link', { name: m['screen.3-3.next'] ?? '' })
      .waitFor({ timeout: RUN_TIMEOUT + 300_000 });
    await expect(page.getByText(m['p3.stack.reset'] ?? '', { exact: true })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    // 3-4, then 3-5: the part's wrap-up, whose main button starts part 4.
    await next(page, m['screen.3-3.next'] ?? '', /\/try\/summary\/learning$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.3-4.title'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.3-4.next'] ?? '', /\/try\/summary\/learning\/end/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.3-5.title'] ?? '');
    await expect(mainButton(page)).toHaveAttribute('href', '/part/4');
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });

  test(`parts 4 and 5 walk to the end with one real resend (${language})`, async ({ page }) => {
    test.setTimeout(RUN_TIMEOUT + 240_000);
    await page.goto(`/part/4?lng=${language}`);
    await briefing(page, m, 4);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.4-0.title'] ?? '');
    expect(await seriousViolations(page)).toEqual([]);

    // 4-1: Send is the one main button; the run plays on 1-3's address and leads back here, then on to the result.
    await next(page, m['screen.4-0.next'] ?? '', /\/try\/timing\/try/);
    await expect(mainButton(page)).toHaveText(m['p1.predict.send'] ?? '');
    await mainButton(page).click();
    await page.waitForURL(/\/try\/attacker\/run/);
    // The second request is the visitor's own (visitorSends): sent from the run as a visitor would.
    await page.getByRole('button', { name: m['p1.run.sendNext'] ?? '' }).click({ timeout: RUN_TIMEOUT });
    await page
      .getByRole('link', { name: m['timing.try.backToResend'] ?? '' })
      .waitFor({ timeout: RUN_TIMEOUT });
    await next(page, m['timing.try.backToResend'] ?? '', /\/try\/timing\/try/);
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.4-1.next'] ?? '', /\/try\/timing\/compare/);
    await expect(page.locator('[data-zone="body"] table')).toHaveCount(1);
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.4-2.next'] ?? '', /\/try\/timing\/when/);
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.4-3.next'] ?? '', /\/try\/timing\/end/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.4-4.title'] ?? '');
    await expect(mainButton(page)).toHaveAttribute('href', '/part/5');

    // Part 5: the five approaches, the numbers with the rule's note (fairness), six cards, four facts and the end.
    await next(page, m['screen.4-4.next'] ?? '', /\/part\/5/);
    await briefing(page, m, 5);
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.5-0.next'] ?? '', /\/try\/summary\/dilemma/);
    await expect(page.getByText(m['p5.dilemma.note'] ?? '', { exact: true })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.5-1.next'] ?? '', /\/try\/summary\/recap/);
    await expect(page.locator('ol[data-count="exempt"] > li')).toHaveCount(6);
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.5-2.next'] ?? '', /\/try\/summary\/adopt/);
    expect(await seriousViolations(page)).toEqual([]);
    await next(page, m['screen.5-3.next'] ?? '', /\/try\/summary\/end/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(m['screen.5-4.title'] ?? '');
    for (const to of ['/lab', '/benchmark', '/adopt']) {
      await expect(page.locator(`[data-zone="body"] a[href="${to}"]`)).toHaveCount(1);
    }
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
  });
}
