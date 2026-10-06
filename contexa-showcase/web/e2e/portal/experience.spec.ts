import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The hands-on experience on the real portal (docs/showcase/체험우선-설계.md, UX-FE-02): the visitor presses the
 * button and the export really goes to the five security approaches, as the attacker, then as the real owner, then
 * under a changed condition. It needs a portal with live runs on and limits high enough for the runs of a whole pass.
 */
const COPY = {
  ko: {
    send: /건 내보내기 요청 보내기/,
    done: '응답이 모두 도착했습니다',
    giveUp: '포기하고 결과 보기',
    next1: '장면 2: 진짜 담당자라면?',
    next2: '두 장면 비교하기',
    winners: /^둘 다 맞힌 곳:/,
    time: '오후 2:20',
    changed: /바꾼 조건: 회사 시각 새벽 3:17 → 오후 2:20/,
  },
  en: {
    send: /Send the request to export/,
    done: 'All answers are in',
    giveUp: 'Give up and see the result',
    next1: 'Scene 2: what if it is the real owner?',
    next2: 'Compare the two scenes',
    winners: /^Got both right:/,
    time: '2:20 pm',
    changed: /Changed: Company time 3:17 am, dawn → 2:20 pm/,
  },
} as const;

const RUN_TIMEOUT = 120_000;

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

test.describe.configure({ mode: 'serial' });

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(' ')).join(', ')}`);
}

async function noHorizontalScroll(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

/** Presses the scene's button and waits for every live answer; the attacker gives up an identity check. */
async function send(scene: Locator, copy: (typeof COPY)['ko' | 'en']) {
  await scene.getByRole('button', { name: copy.send }).click();
  const done = scene.getByText(copy.done);
  const giveUp = scene.getByRole('button', { name: copy.giveUp });
  await expect(done.or(giveUp)).toBeVisible({ timeout: RUN_TIMEOUT });
  if (await giveUp.isVisible()) {
    await giveUp.click();
    await expect(done).toBeVisible({ timeout: RUN_TIMEOUT });
  }
  // Every lane holds a real answer: an outcome, never a waiting or sending lane.
  await expect(scene.locator('li[data-control][data-state="done"]')).toHaveCount(5);
}

for (const language of ['ko', 'en'] as const) {
  test(`experience ${language}: attacker, real owner, comparison, a changed condition`, async ({ page }, info) => {
    test.setTimeout(4 * RUN_TIMEOUT);
    const copy = COPY[language];
    await page.goto(`/?lng=${language}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.locator('section[aria-labelledby="scene-attack"] li[data-state="waiting"]')).toHaveCount(5);
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);

    const attack = page.locator('section[aria-labelledby="scene-attack"]');
    await send(attack, copy);
    await expect(attack.locator('[class*="expect"]')).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    expect(await noHorizontalScroll(page)).toBe(true);

    await page.getByRole('button', { name: copy.next1 }).click();
    const owner = page.locator('section[aria-labelledby="scene-owner"]');
    await send(owner, copy);
    await page.getByRole('button', { name: copy.next2 }).click();
    await expect(page.getByText(copy.winners)).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);

    if (info.project.name === 'chromium') {
      const free = page.locator('section[aria-labelledby="scene-free"]');
      await free.getByRole('button', { name: copy.time, exact: true }).click();
      await send(free, copy);
      await expect(free.getByText(copy.changed)).toBeVisible();
      await free.locator('li[data-control="D"]').getByRole('button').click();
      await expect(page.getByRole('dialog')).toBeVisible();
      expect(await seriousViolations(page)).toEqual([]);
    }
    expect(await noHorizontalScroll(page)).toBe(true);
    if (evidenceDir) {
      await page.screenshot({
        path: join(evidenceDir, `experience-${info.project.name}-${language}.png`),
        fullPage: true,
      });
    }
  });
}

test('experience with the keyboard only', async ({ page }, info) => {
  test.skip(info.project.name !== 'chromium', 'keyboard path is checked once on desktop');
  test.setTimeout(2 * RUN_TIMEOUT);
  await page.goto('/?lng=en');
  const sendButton = page
    .locator('section[aria-labelledby="scene-attack"]')
    .getByRole('button', { name: COPY.en.send });
  for (let presses = 0; presses < 30 && !(await sendButton.evaluate((element) => element === document.activeElement)); presses++) {
    await page.keyboard.press('Tab');
  }
  await expect(sendButton).toBeFocused();
  await page.keyboard.press('Enter');
  const next = page.getByRole('button', { name: COPY.en.next1 });
  const giveUp = page.getByRole('button', { name: COPY.en.giveUp });
  await expect(next.or(giveUp)).toBeVisible({ timeout: RUN_TIMEOUT });
  if (await giveUp.isVisible()) {
    await giveUp.focus();
    await page.keyboard.press('Enter');
  }
  for (let presses = 0; presses < 80 && !(await next.evaluate((element) => element === document.activeElement)); presses++) {
    await page.keyboard.press('Tab');
  }
  await expect(next).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('section[aria-labelledby="scene-owner"]')).toBeVisible();
});
