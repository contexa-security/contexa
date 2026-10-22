import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

/**
 * FC-2 and FC-3 on a real portal (최종화면-구현계획 4절, IN-6): the main flow from the start to its last screen in both
 * languages, with five real sends (the stolen account, the owner's same request, the owner checked on the way, the
 * insider's documents, the attack with one condition changed). On
 * every screen the values are checked against the portal's own answers: the run's step results, its anatomy, the facts
 * of its sealed prompt and its quality record, the comparison of two runs, the lab's delta and the benchmark. Every
 * screen also has no serious accessibility violation and no sideways scroll. It needs a portal with live runs on, no
 * human check and the daily limits high enough for three runs per language.
 */
type Dictionary = Record<string, string>;
const MESSAGES: Record<'ko' | 'en', Dictionary> = {
  ko: JSON.parse(readFileSync(new URL('../../src/i18n/ko.json', import.meta.url), 'utf-8')) as Dictionary,
  en: JSON.parse(readFileSync(new URL('../../src/i18n/en.json', import.meta.url), 'utf-8')) as Dictionary,
};
const RUN_TIMEOUT = 180_000;

test.describe.configure({ mode: 'serial' });

interface Layer {
  readonly control: string;
  readonly httpStatus: number | null;
  readonly evidence: { readonly deliveredItems: number };
}

function format(template: string, values: Readonly<Record<string, string | number>>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(values[key] ?? ''));
}

/**
 * An engine input line as 4-3 states it (src/pages/main/inputLine.ts): a comparison with the usual pattern by its
 * dimension's plain name and its membership in words, any other input under its own label.
 */
function inputLine(m: Dictionary, key: string, value: string | null): string {
  if (!key.startsWith('dim.')) {
    return `${key}: ${value ?? '-'}`;
  }
  const name = m[key] ?? key.slice(4);
  if (value === null) {
    return `${name}: -`;
  }
  const at = value.lastIndexOf(' · ');
  const label = at < 0 ? null : value.slice(at + 3);
  const state = label === 'false' ? 'dim.different' : label === 'true' ? 'dim.same' : null;
  return state === null ? `${name}: ${value}` : `${name}: ${value.slice(0, at)} · ${m[state] ?? state}`;
}

function count(value: number, language: 'ko' | 'en'): string {
  return value.toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US');
}

async function api<T>(page: Page, path: string): Promise<T> {
  const body = await page.evaluate(
    (target) => fetch(target).then((response) => (response.ok ? response.json() : null)),
    path,
  );
  if (body === null) {
    throw new Error(`no answer from ${path}`);
  }
  return body as T;
}

/** Waits until the screen's animations that end have ended (10 s at most), so the checks judge it at rest. */
async function settled(page: Page) {
  await page.evaluate(() =>
    Promise.race([
      Promise.all(
        document
          .getAnimations()
          .filter((animation) => animation.effect?.getTiming().iterations !== Infinity)
          .map((animation) => animation.finished.catch(() => undefined)),
      ),
      new Promise((resolve) => setTimeout(resolve, 10_000)),
    ]),
  );
}

async function checkScreen(page: Page, where: string) {
  await settled(page);
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  const serious = results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map(
      (violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(' ')).join(', ')}`,
    );
  expect.soft(serious, `accessibility on ${where}`).toEqual([]);
  expect
    .soft(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
      `no sideways scroll on ${where}`,
    )
    .toBe(true);
}

function mainButton(page: Page) {
  return page.locator('[data-zone="actions"] [data-main]');
}

/** The console of each send screen's number. */
const CONSOLES = {
  '2-2': /\/attack\/console/,
  '4-2': /\/normal\/console/,
  '5-2': /\/insider\/console/,
} as const;

/** Sends a request from 2-1, 4-1 or 5-1 with a call picked, and waits on the console for the judgment. */
async function send(
  page: Page,
  m: Dictionary,
  call: 'ALLOW' | 'BLOCK',
  number: keyof typeof CONSOLES,
  timeout = RUN_TIMEOUT,
) {
  await page.getByText(m[`main.request.call.${call}`] ?? '', { exact: true }).click();
  await mainButton(page).click();
  await page.waitForURL(CONSOLES[number]);
  await expect(mainButton(page)).toHaveText(new RegExp(m[`main.${number}.cta`] ?? ''), { timeout });
  // The console reads the run's own records once the portal stored the run.
  await expect
    .poll(async () => (await api<{ status: string }>(page, '/api/live/runs/current')).status, {
      timeout: RUN_TIMEOUT,
    })
    .toBe('COMPLETED');
}

/**
 * Follows the 4-4 run until it has ended, asking for each extra check's code and confirming it from the demo inbox as
 * a real user would; returns how the run ended.
 */
async function answerChecks(page: Page, m: Dictionary): Promise<string> {
  const deadline = Date.now() + RUN_TIMEOUT * 2;
  let status = '';
  while (Date.now() < deadline) {
    const run = await api<{ scenario: string; status: string }>(page, '/api/live/runs/current');
    status = run.scenario === 'S14' ? run.status : '';
    if (['COMPLETED', 'FAILED', 'EXPIRED'].includes(status)) {
      return status;
    }
    const useCode = page.getByRole('button', { name: m['try.challenge.useCode'] ?? '' });
    const requestCode = page.getByRole('button', { name: m['try.challenge.requestCode'] ?? '' });
    if (await useCode.isVisible().catch(() => false)) {
      await useCode.click();
    } else if (await requestCode.isVisible().catch(() => false)) {
      await requestCode.click();
    }
    await page.waitForTimeout(1_000);
  }
  return status;
}

/** The console's lanes against the run's stored step result and anatomy. */
async function consoleMatches(page: Page, m: Dictionary, language: 'ko' | 'en', runId: string) {
  const result = await api<{ layers: readonly Layer[] }>(page, `/api/runs/${runId}/steps/1/result`);
  const lanes = page.locator('li[data-control]');
  await expect(lanes).toHaveCount(5);
  for (const layer of result.layers) {
    await expect
      .soft(page.locator(`li[data-control="${layer.control}"]`), `lane ${layer.control}`)
      .toContainText(`HTTP ${layer.httpStatus ?? '—'}`);
  }
  const legacy = result.layers.find((layer) => layer.control === 'B');
  if (legacy) {
    await expect(
      page
        .getByText(format(m['main.items'] ?? '', { items: count(legacy.evidence.deliveredItems, language) }))
        .first(),
    ).toBeVisible();
  }
  const anatomy = await api<{
    interpretation: { recorded: { finalAction: string; riskScore: number | null } };
  }>(page, `/api/runs/${runId}/steps/1/anatomy`);
  const recorded = anatomy.interpretation.recorded;
  await expect
    .soft(page.locator('li[data-control="D"]'))
    .toContainText(m[`main.verdict.${recorded.finalAction}`] ?? recorded.finalAction);
  if (recorded.riskScore !== null) {
    await expect.soft(page.getByText(recorded.riskScore.toFixed(2), { exact: true })).toBeVisible();
  }
  return recorded.finalAction;
}

for (const language of ['ko', 'en'] as const) {
  const m = MESSAGES[language];

  test(`the main flow from the start to its end, its values the portal's records (${language})`, async ({
    page,
  }) => {
    // Five live sends, two of them three requests a minute apart (4-4 and the insider's documents).
    test.setTimeout(7 * RUN_TIMEOUT + 300_000);

    // 1-1 and 1-2: the statement, today's runs and the measured badges.
    await page.goto(`/?lng=${language}`);
    await expect(page.locator('main h1')).toHaveText(m['main.1-1.title'] ?? '');
    const stats = await api<{ runs: { today: number }; engineDecisions: number }>(page, '/api/stats');
    await expect(page.locator('[data-zone="top"]')).toContainText(count(stats.engineDecisions, language));
    await checkScreen(page, '1-1');
    await mainButton(page).click();
    await page.waitForURL(/\/intro\/map/);
    const benchmark = await api<{
      scope: { runs: number; attackRuns: number; normalRuns: number };
      cases: readonly {
        key: string;
        classification: string;
        runs: number;
        results: Record<string, Record<string, number>>;
        cells: Record<string, { right: number; counted: number }>;
        runResults: Record<string, Record<string, string>>;
      }[];
      controls: readonly { control: string; missed: number; falseBlock: { hits: number; total: number } }[];
    }>(page, '/api/benchmark');
    // The badges of the two themes' cases (IN-6): the stolen account and the insider.
    for (const key of ['S13', 'S16']) {
      const measured = benchmark.cases.find((found) => found.key === key);
      if (measured?.cells.D) {
        await expect(page.locator('main')).toContainText(
          format(m['main.1-2.badge.measured'] ?? '', {
            right: measured.cells.D.right,
            counted: measured.cells.D.counted,
          }),
        );
      }
    }
    await expect(page.getByRole('region', { name: m['theme.outside.name'] ?? '' })).toBeVisible();
    await expect(page.getByRole('region', { name: m['theme.inside.name'] ?? '' })).toBeVisible();
    await expect(page.locator('main')).toContainText(
      format(m['main.1-2.badge.runs'] ?? '', { runs: benchmark.scope.runs }),
    );
    await checkScreen(page, '1-2');

    // 2-0 and 2-1: the cover, then the request as the case defines it and the request line the engine received.
    await mainButton(page).click();
    await page.waitForURL(/\/attack$/);
    await expect(page.locator('main h1')).toHaveText(m['cover.2.question'] ?? '');
    await checkScreen(page, '2-0');
    await mainButton(page).click();
    await page.waitForURL(/\/attack\/request/);
    const before = await api<{ comparison: { runId: string } | null }>(page, '/api/live/before/S13?step=1');
    if (before.comparison) {
      const latest = await api<{ context: { resource: { httpMethod: string; requestPath: string } } }>(
        page,
        `/api/runs/${before.comparison.runId}/steps/1/anatomy`,
      );
      await expect(page.locator('main code').first()).toContainText(
        `${latest.context.resource.httpMethod} ${latest.context.resource.requestPath}`,
      );
    }
    await checkScreen(page, '2-1');

    // 2-2: the live console.
    await send(page, m, 'BLOCK', '2-2');
    const attack = await api<{ runId: string }>(page, '/api/live/runs/current');
    const attackAction = await consoleMatches(page, m, language, attack.runId);
    await checkScreen(page, '2-2');

    // 2-3: the headline from the record, the size ratio and the company facts of the run.
    await mainButton(page).click();
    await page.waitForURL(/\/attack\/result/);
    const received = await api<{
      sizeRatio: { times: number } | null;
      businessFacts: readonly { code: string; value: string | null }[];
      departureCount: number;
    }>(page, `/api/runs/${attack.runId}/steps/1/received`);
    if (['ESCALATE', 'BLOCK', 'CHALLENGE'].includes(attackAction)) {
      await expect(page.locator('main h1')).toHaveText(m[`main.2-3.title.${attackAction}`] ?? '');
    }
    if (received.sizeRatio) {
      await expect(page.locator('main')).toContainText(
        format(m['main.2-3.size.line'] ?? '', { times: count(received.sizeRatio.times, language) }),
      );
    }
    await expect(page.locator('[data-guide]')).toContainText(
      format(m['main.2-3.intro'] ?? '', { n: received.departureCount }),
    );
    await checkScreen(page, '2-3');

    // 3-0 to 3-3: the run laid open, every value its stored record.
    await mainButton(page).click();
    await page.waitForURL(/\/evidence$/);
    await checkScreen(page, '3-0');
    await mainButton(page).click();
    await page.waitForURL(/\/evidence\/map/);
    const anatomy = await api<{ promptLines: { total: number; system: number; user: number } | null }>(
      page,
      `/api/runs/${attack.runId}/steps/1/anatomy`,
    );
    const quality = await api<{
      seal: { packageHash: string | null } | null;
      reasonCodes: readonly { code: string; fact: string | null }[];
    }>(page, `/api/runs/${attack.runId}/steps/1/quality`);
    if (anatomy.promptLines) {
      await expect(page.locator('main')).toContainText(
        format(m['main.3-1.prompt.line'] ?? '', {
          system: count(anatomy.promptLines.system, language),
          user: count(anatomy.promptLines.user, language),
          total: count(anatomy.promptLines.total, language),
        }),
      );
    }
    const hash = quality.seal?.packageHash ?? null;
    if (hash) {
      await expect(page.locator('main')).toContainText(`${hash.slice(0, 6)}…${hash.slice(-4)}`);
    }
    await checkScreen(page, '3-1');
    await mainButton(page).click();
    await page.waitForURL(/\/evidence\/prompt/);
    const facts = await api<{ blocks: readonly { facts: readonly { line: number; label: string }[] }[] }>(
      page,
      `/api/runs/${attack.runId}/steps/1/facts`,
    );
    for (const label of ['BaselineStatus', 'UsualHours', 'PolicySatisfied', 'ResourceClass']) {
      const fact = facts.blocks
        .flatMap((block) => block.facts)
        .find((candidate) => candidate.label === label);
      if (fact) {
        await expect.soft(page.locator('main'), label).toContainText(`${String(fact.line).padStart(3, '0')}`);
        await expect.soft(page.locator('main'), label).toContainText(label);
      }
    }
    await checkScreen(page, '3-2');
    await mainButton(page).click();
    await page.waitForURL(/\/evidence\/verdict/);
    for (const code of quality.reasonCodes) {
      await expect.soft(page.locator('main')).toContainText(code.code);
    }
    await checkScreen(page, '3-3');

    // 4-0 to 4-3: the real user's request, then the one line apart from the server's comparison of the two runs.
    await mainButton(page).click();
    await page.waitForURL(/\/normal$/);
    await checkScreen(page, '4-0');
    await mainButton(page).click();
    await page.waitForURL(/\/normal\/request/);
    await checkScreen(page, '4-1');
    await send(page, m, 'ALLOW', '4-2');
    const normal = await api<{ runId: string }>(page, '/api/live/runs/current');
    await consoleMatches(page, m, language, normal.runId);
    await checkScreen(page, '4-2');
    await mainButton(page).click();
    await page.waitForURL(/\/normal\/diff/);
    const changes = await api<readonly { key: string; before: string | null; now: string | null }[]>(
      page,
      `/api/runs/${normal.runId}/steps/1/input-changes?against=${attack.runId}`,
    );
    await expect(page.locator('[data-guide]')).toContainText(
      format(m['main.4-3.intro'] ?? '', { n: changes.length }),
    );
    // The two cases are defined alike but for the device (IN-6), so the headline names that row.
    await expect(page.locator('main h1')).toHaveText(
      format(m['main.4-3.title.one'] ?? '', { row: m['main.request.row.place'] ?? '' }),
    );
    for (const change of changes) {
      await expect.soft(page.locator('main')).toContainText(inputLine(m, change.key, change.before));
      await expect.soft(page.locator('main')).toContainText(inputLine(m, change.key, change.now));
    }
    await checkScreen(page, '4-3');

    // 4-4: the real user checked on the way (FU-3), sent live; every extra check is answered with the demo inbox's
    // code, and each request's resend and the headline are the run's own records.
    await mainButton(page).click();
    await page.waitForURL(/\/normal\/check/);
    await checkScreen(page, '4-4 before');
    await mainButton(page).click();
    const checkStatus = await answerChecks(page, m);
    expect(checkStatus).toBe('COMPLETED');
    const checked = await api<{ runId: string }>(page, '/api/live/runs/current');
    for (const stepNo of [1, 2, 3]) {
      const anatomy = await api<{
        recovery: {
          challenge: {
            answered: boolean;
            reissue_status: number | null;
            reissue_delivered: number | null;
          } | null;
        } | null;
      }>(page, `/api/runs/${checked.runId}/steps/${stepNo}/anatomy`);
      const check = anatomy.recovery?.challenge ?? null;
      if (check?.answered && check.reissue_status !== null) {
        await expect.soft(page.locator('main'), `request ${stepNo} sent again`).toContainText(
          format(
            m[check.reissue_delivered === 1 ? 'main.recovery.retried_one' : 'main.recovery.retried'] ?? '',
            {
              items: count(check.reissue_delivered ?? 0, language),
              status: check.reissue_status,
            },
          ),
        );
      }
    }
    const journey = await api<{ runs: readonly { runId: string; business: Record<string, string> }[] }>(
      page,
      '/api/journey',
    );
    const checkedContexa = journey.runs.find((line) => line.runId === checked.runId)?.business['D'];
    await expect(page.locator('main h1')).toHaveText(
      m[
        checkedContexa === 'PASSED_AFTER_CHECK'
          ? 'main.4-4.title.afterCheck'
          : checkedContexa === 'PASSED'
            ? 'main.4-4.title.through'
            : 'main.4-4.title.other'
      ] ?? '',
    );
    await checkScreen(page, '4-4');

    // 5-0 to 5-3 (IN-6): the insider's documents sent live, one row per document, then what the AI weighed.
    await mainButton(page).click();
    await page.waitForURL(/\/insider$/);
    await expect(page.locator('main h1')).toHaveText(m['cover.5.question'] ?? '');
    await checkScreen(page, '5-0');
    await mainButton(page).click();
    await page.waitForURL(/\/insider\/request/);
    await checkScreen(page, '5-1');
    // The insider's three documents go a minute apart.
    await send(page, m, 'BLOCK', '5-2', 2 * RUN_TIMEOUT);
    const insider = await api<{ runId: string }>(page, '/api/live/runs/current');
    await expect(page.locator('li[data-step]')).toHaveCount(3);
    await checkScreen(page, '5-2');
    await mainButton(page).click();
    await page.waitForURL(/\/insider\/reason/);
    const insiderAnatomy = await api<{ interpretation: { recorded: { finalAction: string | null } } }>(
      page,
      `/api/runs/${insider.runId}/steps/1/anatomy`,
    );
    const insiderAction = insiderAnatomy.interpretation.recorded.finalAction;
    if (insiderAction) {
      await expect(page.locator('main')).toContainText(m[`main.verdict.${insiderAction}`] ?? insiderAction);
    }
    const insiderQuality = await api<{ hypotheses?: readonly { id: string }[] }>(
      page,
      `/api/runs/${insider.runId}/steps/1/quality`,
    );
    if ((insiderQuality.hypotheses ?? []).length > 0) {
      await expect(page.getByRole('heading', { name: m['main.3-3.hypothesesTitle'] ?? '' })).toBeVisible();
    }
    const s16 = benchmark.cases.find((found) => found.key === 'S16');
    for (const [result, n] of Object.entries(s16?.results.C1 ?? {})) {
      await expect.soft(page.locator('main')).toContainText(
        format(m['main.5-3.count'] ?? '', {
          word: m[`main.result.${result}`] ?? result,
          n,
          runs: s16?.runs ?? 0,
        }),
      );
    }
    await checkScreen(page, '5-3');

    // 6-0 to 6-3: the rule switch, one condition changed and sent for real, every run.
    await mainButton(page).click();
    await page.waitForURL(/\/compare$/);
    await checkScreen(page, '6-0');
    await mainButton(page).click();
    await page.waitForURL(/\/compare\/rule/);
    const visited = await api<{ runs: readonly { scenarioKey: string; business: Record<string, string> }[] }>(
      page,
      '/api/journey',
    );
    const ownAttack = [...visited.runs].reverse().find((line) => line.scenarioKey === 'S13')?.business ?? {};
    const ownWork = [...visited.runs].reverse().find((line) => line.scenarioKey === 'S13T')?.business ?? {};
    const variant =
      ownAttack['C1'] === 'STOPPED' && ownWork['C1'] === 'HALTED'
        ? ''
        : ownAttack['C1'] === 'MISSED' && ['PASSED', 'PASSED_AFTER_CHECK'].includes(ownWork['C1'] ?? '')
          ? '.blind'
          : 'Plain';
    await expect(page.locator('main h1')).toHaveText(m[`main.6-1.title${variant}`] ?? '');
    const switcher = page.getByRole('switch');
    await expect(switcher).toBeChecked();
    await switcher.uncheck();
    await expect(page.locator('main')).toContainText(m['main.6-1.off'] ?? '');
    await switcher.check();
    await checkScreen(page, '6-1');
    await mainButton(page).click();
    await page.waitForURL(/\/compare\/change/);
    await page.getByRole('button', { name: m['main.6-2.send'] ?? '' }).click();
    await page.waitForURL(/sent=/, { timeout: 30_000 });
    await expect(page.locator('li[data-control="D"]')).toContainText(
      new RegExp(
        ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'].map((action) => m[`main.verdict.${action}`]).join('|'),
      ),
      { timeout: RUN_TIMEOUT },
    );
    await expect
      .poll(async () => (await api<{ status: string }>(page, '/api/live/runs/current')).status, {
        timeout: RUN_TIMEOUT,
      })
      .toBe('COMPLETED');
    const lab = await api<{ runId: string }>(page, '/api/live/runs/current');
    await expect
      .poll(
        async () => (await api<{ available: boolean }>(page, `/api/lab/runs/${lab.runId}/delta`)).available,
        {
          timeout: 60_000,
        },
      )
      .toBe(true);
    const delta = await api<{ steps: readonly { stepNo: number; changed: readonly { label: string }[] }[] }>(
      page,
      `/api/lab/runs/${lab.runId}/delta`,
    );
    for (const line of delta.steps.find((step) => step.stepNo === 1)?.changed ?? []) {
      await expect.soft(page.locator('main')).toContainText(`+ ${line.label}`, { timeout: 30_000 });
    }
    await checkScreen(page, '6-2');
    await mainButton(page).click();
    await page.waitForURL(/\/compare\/runs/);
    const scored = (classification: string) =>
      benchmark.cases
        .filter((found) => found.classification === classification)
        .flatMap((found) => Object.values(found.runResults))
        .filter((results) => results.D !== undefined).length;
    await expect(page.locator('[data-dot]')).toHaveCount(3 * (scored('THREAT') + scored('NORMAL')));
    for (const control of benchmark.controls.filter((score) => ['C1', 'C2', 'D'].includes(score.control))) {
      await expect
        .soft(page.locator('main'))
        .toContainText(
          format(m['main.6-3.rowSum'] ?? '', { missed: control.missed, falseBlock: control.falseBlock.hits }),
        );
    }
    await checkScreen(page, '6-3');

    // 7-1 and 7-2: the three numbers from their records, and the three ways on.
    await mainButton(page).click();
    await page.waitForURL(/\/summary$/);
    const contexa = benchmark.controls.find((score) => score.control === 'D');
    if (contexa) {
      await expect(page.locator('main')).toContainText(
        `${count(contexa.falseBlock.hits, language)} / ${count(contexa.falseBlock.total, language)}`,
        { timeout: 5_000 },
      );
    }
    const promptQuality = await api<{ reasonMatch: { hits: number; total: number } }>(
      page,
      '/api/benchmark/prompt-quality',
    );
    await expect(page.locator('main')).toContainText(
      `${count(promptQuality.reasonMatch.hits, language)} / ${count(promptQuality.reasonMatch.total, language)}`,
      { timeout: 5_000 },
    );
    await checkScreen(page, '7-1');
    await mainButton(page).click();
    await page.waitForURL(/\/summary\/next/);
    for (const to of ['/adopt', '/benchmark', '/more']) {
      await expect(page.locator(`main a[href="${to}"]`)).toBeVisible();
    }
    await checkScreen(page, '7-2');
  });
}

test('an old address leads to the screen of the new flow that took its place', async ({ page }) => {
  for (const [from, to] of [
    ['/part/1', '/attack'],
    ['/try/attacker/predict', '/attack/request'],
    ['/try/owner/result', '/normal/diff'],
    ['/try/summary/recap', '/summary'],
    ['/try/prompt', '/evidence/prompt'],
    ['/compare/inside', '/insider/reason'],
  ] as const) {
    await page.goto(`${from}?lng=ko`);
    await page.waitForURL(new RegExp(`${to.replace(/\//g, '\\/')}(\\?.*)?$`));
  }
});
