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
  readonly runId: string;
  readonly agreeing: number;
  readonly repetitions: number;
  readonly layers: readonly {
    readonly control: string;
    readonly outcome: string;
    readonly verdict: string | null;
    readonly evidence: { readonly deliveredItems: number };
  }[];
}

interface StoredScore {
  readonly title: { readonly en: string } | null;
  readonly truth: { readonly classification: string | null };
}

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

/** The screens' one way to write seconds (src/journey/format.ts). */
function seconds(ms: number): string {
  return ms >= 1000 ? (ms / 1000).toFixed(1) : (ms / 1000).toFixed(2);
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
 * The stored real record (D-35, T-111) on real recordings: every published pair replays each recorded run as one
 * column of the first screen's replay, every rule row and Contexa's row as the record says, the case's right answer
 * from the run's score and the measurement line from the recording.
 */
test('every published replay renders exactly its recorded results', async ({ page, request }, info) => {
  test.skip(info.project.name !== 'chromium', 'record comparison is checked once');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  for (const pair of await recordings(request)) {
    await page.goto(`/replay/${pair.key}?lng=en`);
    for (const { scene, score } of pair.scenes) {
      const normal = score.truth.classification === 'NORMAL';
      const title = score.title?.en ?? word('detail.unnamed');
      const column = page.locator('section').filter({ has: page.getByRole('heading', { name: title }) });
      await expect(column).toContainText(word(normal ? 'hook.answer.pass' : 'hook.answer.stop'));
      for (const layer of scene.layers) {
        if (layer.control === 'C1' || layer.control === 'C2') {
          const expected =
            layer.outcome === 'DELIVERED'
              ? word('hook.passed')
              : word(normal ? 'hook.halted' : 'hook.stopped');
          await expect(column.locator(`li[data-row="${layer.control}"] > span:nth-child(2)`)).toHaveText(
            expected,
          );
        }
        if (layer.control === 'D') {
          const result =
            layer.verdict === 'ALLOW' && layer.outcome === 'DELIVERED'
              ? word('hook.passed')
              : layer.verdict === 'CHALLENGE'
                ? word('verdict.verify')
                : layer.verdict === 'ESCALATE'
                  ? word('verdict.review')
                  : layer.verdict === 'BLOCK'
                    ? word('verdict.block')
                    : word(layer.outcome === 'DELIVERED' ? 'hook.passed' : 'hook.stopped');
          await expect(column.locator('li[data-row="D"] > span:nth-child(2)')).toHaveText(
            fill(word('hook.withItems'), {
              result,
              items: layer.evidence.deliveredItems.toLocaleString('en-US'),
            }),
          );
        }
      }
      await expect(column).toContainText(
        scene.agreeing === scene.repetitions
          ? fill(word('hook.measuredSame'), { runs: scene.repetitions })
          : fill(word('hook.measuredSome'), { runs: scene.repetitions, same: scene.agreeing }),
      );
    }
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
    for (const [index, { scene, score }] of pair.scenes.entries()) {
      const title = score.title?.en ?? word('detail.unnamed');
      const anatomy = (await (await request.get(`/api/runs/${scene.runId}/steps/1/anatomy`)).json()) as {
        interpretation: { timeline: readonly unknown[]; sinceStartMs: readonly (number | null)[] };
      };
      await page.getByRole('button', { name: fill(word('replay2.detailOf'), { name: title }) }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible();
      await dialog.getByRole('tab', { name: word('detail.tab.process') }).click();
      const stages = dialog.getByRole('tabpanel').locator('ol').first().locator('li > span:first-child');
      await expect(stages).toHaveText(
        anatomy.interpretation.sinceStartMs.map((ms) => fill(word('detail.after'), { s: seconds(ms ?? 0) })),
      );
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
