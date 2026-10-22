import AxeBuilder from '@axe-core/playwright';
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The recorded replays on the real portal (P2-FE-01, P2-FE-03, P3-BE-03): load time of the first screen and of a replay,
 * and every published replay showing exactly its recorded outcomes and timeline. The first screen's hands-on flow is
 * checked by experience.spec.ts.
 */
const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

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

interface RecordedScene {
  readonly kind: 'ATTACK' | 'LEGITIMATE';
  readonly runId: string;
  readonly agreeing: number;
  readonly repetitions: number;
}

interface StoredScore {
  readonly business: Readonly<Record<string, { readonly result: string } | undefined>>;
}

/** The result words of the result screens (src/pages/ReplayPage.tsx RESULT_WORDS). */
const RESULT_WORDS: Readonly<Record<string, string>> = {
  STOPPED: 'p1.result.word.STOPPED',
  PARTLY_STOPPED: 'p1.result.word.PARTLY_STOPPED',
  MISSED: 'p1.result.word.MISSED',
  PASSED: 'p1.result.word.PASSED',
  PASSED_AFTER_CHECK: 'p1.result.word.PASSED_AFTER_CHECK',
  HALTED: 'p1.result.word.HALTED',
  UNRESOLVED: 'p1.result.word.UNRESOLVED',
};
const CONTROLS = ['A', 'B', 'C1', 'C2', 'D'] as const;

const english = JSON.parse(readFileSync(join(process.cwd(), 'src/i18n/en.json'), 'utf-8')) as Record<
  string,
  string
>;

function word(key: string): string {
  const value = english[key];
  if (value === undefined) {
    throw new Error(`missing text ${key}`);
  }
  return value;
}

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? `{{${key}}}`));
}

async function recordings(request: APIRequestContext) {
  const pairs = (await (await request.get('/api/pairs')).json()) as { key: string; recorded: boolean }[];
  const recorded = pairs.filter((pair) => pair.recorded);
  expect(recorded.length).toBeGreaterThan(0);
  return Promise.all(
    recorded.map(async (pair) => {
      const replay = (await (await request.get(`/api/replays/${pair.key}`)).json()) as {
        scenes: readonly RecordedScene[];
      };
      const scenes = await Promise.all(
        replay.scenes.map(async (scene) => ({
          scene,
          score: (await (await request.get(`/api/runs/${scene.runId}/score`)).json()) as StoredScore,
        })),
      );
      return { key: pair.key, scenes };
    }),
  );
}

/**
 * The stored real record (D-35, T-111, R7 RO-5) on real recordings: every published pair shows its two recorded runs
 * side by side, one column per run named by who sent it, every approach's cell the run's score in the result screens'
 * words, and the repeated sends' line from the recording.
 */
test('every published replay renders exactly its recorded results', async ({ page, request }, info) => {
  test.skip(info.project.name !== 'chromium', 'record comparison is checked once');
  for (const pair of await recordings(request)) {
    await page.goto(`/replay/${pair.key}?lng=en`);
    const body = page.locator('[data-zone="body"]');
    await expect(body.locator('table')).toBeVisible();
    for (const [index, { scene, score }] of pair.scenes.entries()) {
      const who = word(scene.kind === 'ATTACK' ? 'p2.result.table.attacker' : 'p2.result.table.owner');
      await expect(body.getByRole('columnheader').nth(index + 1)).toHaveText(who);
      for (const control of CONTROLS) {
        const result = score.business[control]?.result ?? null;
        const key = result ? RESULT_WORDS[result] : undefined;
        const cell = body
          .locator('tr')
          .filter({
            has: page.getByRole('rowheader', { name: word(`control.${control}.name`), exact: true }),
          })
          .locator('td')
          .nth(index);
        if (key) {
          await expect(cell).toContainText(word(key));
        }
      }
    }
    // The source line: the recording's repeated sends and how often they agreed.
    const [first] = pair.scenes;
    const allSame = pair.scenes.every(
      ({ scene }) => scene.agreeing === scene.repetitions && scene.repetitions === first?.scene.repetitions,
    );
    await expect(page.locator('[data-zone="source"]')).toHaveText(
      allSame
        ? fill(word('space.r7.replay.sourceSame'), { runs: first?.scene.repetitions ?? 0 })
        : `${word('space.r7.replay.source')} · ${pair.scenes
            .map(
              ({ scene }) =>
                `${word(scene.kind === 'ATTACK' ? 'p2.result.table.attacker' : 'p2.result.table.owner')}: ${
                  scene.agreeing === scene.repetitions
                    ? fill(word('space.r7.replay.repeat.same'), { runs: scene.repetitions })
                    : fill(word('space.r7.replay.repeat.some'), {
                        runs: scene.repetitions,
                        same: scene.agreeing,
                      })
                }`,
            )
            .join(', ')}`,
    );
    expect(await seriousViolations(page)).toEqual([]);
    if (evidenceDir) {
      await page.screenshot({ path: join(evidenceDir, `replay-${pair.key}.png`), fullPage: true });
    }
  }
});

/**
 * P3-BE-03 on real recordings: each recorded run opens its decision details over the record, whose steps show exactly
 * the times after the first the portal serves; the browser's back button closes them and leaves the record.
 */
test('every published replay leads to the decision details and its recorded analysis timeline', async ({
  page,
  request,
}, info) => {
  test.skip(info.project.name !== 'chromium', 'record comparison is checked once');
  for (const pair of await recordings(request)) {
    await page.goto(`/replay/${pair.key}?lng=en`);
    const address = page.url();
    for (const [index, { scene }] of pair.scenes.entries()) {
      const who = word(scene.kind === 'ATTACK' ? 'p2.result.table.attacker' : 'p2.result.table.owner');
      const anatomy = (await (await request.get(`/api/runs/${scene.runId}/steps/1/anatomy`)).json()) as {
        interpretation: { timeline: readonly unknown[]; sinceStartMs: readonly (number | null)[] };
      };
      await page.getByRole('button', { name: fill(word('space.r7.replay.detailOf'), { who }) }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible();
      // The judging tab walks the nine steps of 3-2 with this request's values (R7-검수 V-47).
      await dialog.getByRole('tab', { name: word('detail.r7.tab.process') }).click();
      await expect(dialog.getByRole('tabpanel').locator('ol').first().locator(':scope > li')).toHaveCount(9);
      expect(anatomy.interpretation.timeline.length).toBeGreaterThan(0);
      expect(await seriousViolations(page)).toEqual([]);
      if (evidenceDir) {
        await page.screenshot({ path: join(evidenceDir, `timeline-${pair.key}-${index}.png`) });
      }
      await page.goBack();
      await expect(dialog).toBeHidden();
      expect(page.url()).toBe(address);
    }
  }
});
