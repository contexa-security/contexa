import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * P2-FE-02 and P2-FE-04 on the real portal: first screen, vote, screen 1 and the legitimate request that looks the
 * same, in Korean and English, with the keyboard-free click path and the accessibility scan on each screen. The
 * expected words come from the dictionaries; the shown results come from the recorded replay.
 */
const COPY = {
  ko: { block: '차단한다', next: '다음', finished: '두 장면을 모두 보았습니다', prompt: '당신이라면?' },
  en: { block: 'Block it', next: 'Next', finished: 'You have seen both requests', prompt: 'What would you do?' },
} as const;

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(' ')).join(', ')}`);
}

async function noHorizontalScroll(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

for (const language of ['ko', 'en'] as const) {
  test(`quick start ${language}: question, vote, verdict comparison, legitimate request`, async ({ page }, info) => {
    const copy = COPY[language];
    await page.goto(`/?lng=${language}`);
    await expect(page.getByText(copy.prompt)).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
    if (evidenceDir) {
      await page.screenshot({ path: join(evidenceDir, `entry-${info.project.name}-${language}.png`), fullPage: true });
    }

    await page.getByRole('button', { name: copy.block }).click();
    await expect(page).toHaveURL(/\/replay\/A3$/);
    await expect(page.locator('article[data-control="D"]')).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);
    if (evidenceDir) {
      await page.screenshot({ path: join(evidenceDir, `replay-${info.project.name}-${language}.png`), fullPage: true });
    }

    await page.getByRole('button', { name: copy.next, exact: true }).click();
    await expect(page.getByText(copy.finished)).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
  });
}

test('quick start with the keyboard only', async ({ page }, info) => {
  test.skip(info.project.name !== 'chromium', 'keyboard path is checked once on desktop');
  await page.goto('/?lng=en');
  await expect(page.getByText(COPY.en.prompt)).toBeVisible();
  const block = page.getByRole('button', { name: COPY.en.block });
  for (let presses = 0; presses < 20 && !(await block.evaluate((element) => element === document.activeElement)); presses++) {
    await page.keyboard.press('Tab');
  }
  await expect(block).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/replay\/A3$/);
  const next = page.getByRole('button', { name: COPY.en.next, exact: true });
  for (let presses = 0; presses < 60 && !(await next.evaluate((element) => element === document.activeElement)); presses++) {
    await page.keyboard.press('Tab');
  }
  await expect(next).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByText(COPY.en.finished)).toBeVisible();
});

/**
 * P2-FE-03: largest contentful paint under a slow 4G profile (Lighthouse mobile: 150 ms round trip, 1.6 Mbit/s down,
 * 750 kbit/s up, CPU four times slower), for the first screen and screen 1.
 */
test('largest contentful paint on slow 4G', async ({ page, context }, info) => {
  test.skip(info.project.name !== 'chromium', 'network emulation needs Chromium');
  const session = await context.newCDPSession(page);
  await session.send('Network.enable');
  await session.send('Network.emulateNetworkConditions', {
    offline: false,
    latency: 150,
    downloadThroughput: (1.6 * 1024 * 1024) / 8,
    uploadThroughput: (750 * 1024) / 8,
  });
  await session.send('Emulation.setCPUThrottlingRate', { rate: 4 });
  const results: Record<string, number> = {};
  for (const path of ['/?lng=en', '/replay/A3?lng=en']) {
    await page.goto(path, { waitUntil: 'load' });
    await page.waitForTimeout(1500);
    results[path] = await page.evaluate(
      () =>
        new Promise<number>((resolve) => {
          new PerformanceObserver((list) => {
            const entries = list.getEntries();
            resolve(entries[entries.length - 1]?.startTime ?? -1);
          }).observe({ type: 'largest-contentful-paint', buffered: true });
        }),
    );
  }
  await test.info().attach('lcp-ms', { body: JSON.stringify(results), contentType: 'application/json' });
  for (const value of Object.values(results)) {
    expect(value).toBeGreaterThan(0);
    expect(value).toBeLessThan(2500);
  }
});

/**
 * P2-FE-01 on real recordings: for every published pair, each layer card shows exactly the business outcome and the
 * verdict word of the recorded JSON the portal serves.
 */
test('every published replay renders exactly its recorded outcomes', async ({ page, request }, info) => {
  test.skip(info.project.name !== 'chromium', 'record comparison is checked once');
  const english = JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/en.json'), 'utf-8')) as Record<string, string>;
  const outcomeWords: Record<string, string | undefined> = {
    DELIVERED: english['outcome.delivered'],
    STOPPED: english['outcome.stopped'],
    HELD: english['outcome.held'],
    UNRESOLVED: english['outcome.unresolved'],
  };
  const verdictWords: Record<string, string | undefined> = {
    ALLOW: english['verdict.allow'],
    CHALLENGE: english['verdict.verify'],
    ESCALATE: english['verdict.review'],
    BLOCK: english['verdict.block'],
    PENDING: english['verdict.pending'],
  };
  const pairs = (await (await request.get('/api/pairs')).json()) as { key: string; recorded: boolean }[];
  const recorded = pairs.filter((pair) => pair.recorded);
  expect(recorded.length).toBeGreaterThan(0);
  for (const pair of recorded) {
    const replay = (await (await request.get(`/api/replays/${pair.key}`)).json()) as {
      scenes: { layers: { control: string; outcome: string; verdict: string }[] }[];
    };
    await page.goto(`/replay/${pair.key}?lng=en`);
    for (const [index, scene] of replay.scenes.entries()) {
      if (index > 0) {
        await page.getByRole('button', { name: COPY.en.next, exact: true }).click();
      }
      for (const layer of scene.layers) {
        const card = page.locator(`article[data-control="${layer.control}"]`);
        await expect(card.getByText(outcomeWords[layer.outcome] ?? 'missing', { exact: true })).toBeVisible();
        await expect(card.getByText(verdictWords[layer.verdict] ?? 'missing', { exact: true })).toBeVisible();
      }
    }
  }
});

/**
 * P3-BE-03 on real recordings: the Contexa evidence chain of every published scene shows exactly the milliseconds the
 * portal serves (which p3-timeline-check.py recomputes from the stored event and send times), response included.
 */
test('every published replay shows the recorded analysis timeline', async ({ page, request }, info) => {
  test.skip(info.project.name !== 'chromium', 'record comparison is checked once');
  const number = new Intl.NumberFormat('en-US');
  const pairs = (await (await request.get('/api/pairs')).json()) as { key: string; recorded: boolean }[];
  const recorded = pairs.filter((pair) => pair.recorded);
  expect(recorded.length).toBeGreaterThan(0);
  for (const pair of recorded) {
    const replay = (await (await request.get(`/api/replays/${pair.key}`)).json()) as {
      scenes: {
        layers: { control: string; evidence: { responseMs: number | null; timeline: { atMs: number }[] } }[];
      }[];
    };
    await page.goto(`/replay/${pair.key}?lng=en`);
    for (const [index, scene] of replay.scenes.entries()) {
      if (index > 0) {
        await page.getByRole('button', { name: COPY.en.next, exact: true }).click();
      }
      const engine = scene.layers.find((layer) => layer.control === 'D');
      if (!engine || engine.evidence.timeline.length === 0) {
        continue;
      }
      const values = engine.evidence.timeline.map((event) => event.atMs);
      if (engine.evidence.responseMs !== null) {
        values.push(engine.evidence.responseMs);
      }
      const expected = values.sort((left, right) => left - right).map((value) => `+${number.format(value)} ms`);
      await page.locator('article[data-control="D"]').getByRole('button', { name: /Evidence chain/ }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog.getByText('Analysis timeline')).toBeVisible();
      await expect(dialog.getByTestId('timeline-offset')).toHaveText(expected);
      expect(await seriousViolations(page)).toEqual([]);
      if (evidenceDir) {
        await page.screenshot({ path: join(evidenceDir, `timeline-${pair.key}-${index}.png`) });
      }
      await dialog.getByRole('button', { name: 'Close' }).click();
    }
  }
});
