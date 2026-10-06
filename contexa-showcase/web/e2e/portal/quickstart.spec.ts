import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The recorded replays on the real portal (P2-FE-01, P2-FE-03, P3-BE-03): load time of the first screen and of a replay,
 * and every published replay showing exactly its recorded outcomes and timeline. The first screen's hands-on flow is
 * checked by experience.spec.ts.
 */
const COPY = {
  en: { next: 'Next' },
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
      await page.locator('article[data-control="D"]').getByRole('button', { name: /Reasoning in detail/ }).click();
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
