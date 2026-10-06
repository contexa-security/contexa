import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const VIEWPORTS = [
  { name: 'desktop-1440', width: 1440, height: 900 },
  { name: 'tablet-768', width: 768, height: 1024 },
  { name: 'mobile-390', width: 390, height: 844 },
] as const;

const evidenceDir = process.env.SHOWCASE_EVIDENCE_DIR;
if (evidenceDir) {
  mkdirSync(evidenceDir, { recursive: true });
}

async function seriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  return results.violations.filter((violation) => violation.impact === 'serious' || violation.impact === 'critical');
}

/** Elements whose content is wider than their box, or a page wider than the viewport. */
async function overflowingElements(page: Page) {
  return page.evaluate(() => {
    const offenders: string[] = [];
    if (document.documentElement.scrollWidth > window.innerWidth + 1) {
      offenders.push(`document ${document.documentElement.scrollWidth}>${window.innerWidth}`);
    }
    for (const element of Array.from(document.querySelectorAll('main *'))) {
      const html = element as HTMLElement;
      const style = window.getComputedStyle(html);
      if (style.display === 'none' || style.overflowX === 'auto' || style.overflowX === 'scroll') {
        continue;
      }
      // Visually hidden helpers are 1px boxes by design; they are read by screen readers, not seen.
      if (html.scrollWidth > html.clientWidth + 1 && html.clientWidth > 1) {
        offenders.push(`${html.tagName.toLowerCase()}.${html.className} ${html.scrollWidth}>${html.clientWidth}`);
      }
    }
    return offenders;
  });
}

for (const viewport of VIEWPORTS) {
  for (const scheme of ['dark', 'light'] as const) {
    for (const language of ['ko', 'en'] as const) {
      test(`design mock ${viewport.name} ${scheme} ${language}: no serious accessibility violation, no overflow`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await page.goto(`/design?lng=${language}`);
        await expect(page.getByRole('heading', { name: 'Contexa' })).toBeVisible();
        if (evidenceDir) {
          await page.screenshot({
            path: join(evidenceDir, `design-${viewport.name}-${scheme}-${language}.png`),
            fullPage: true,
          });
        }
        expect(await seriousViolations(page)).toEqual([]);
        expect(await overflowingElements(page)).toEqual([]);
      });
    }
  }

  test(`design mock ${viewport.name}: English stretched by 30 percent still fits`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto('/design?lng=pseudo');
    await expect(page.locator('main')).toBeVisible();
    if (evidenceDir) {
      await page.screenshot({ path: join(evidenceDir, `design-${viewport.name}-pseudo.png`), fullPage: true });
    }
    expect(await overflowingElements(page)).toEqual([]);
  });
}

test('design mock: the evidence chain is reachable and closable with the keyboard only', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/design?lng=en');
  const trigger = page.getByRole('button', { name: /Reasoning in detail — Contexa/ });
  for (let presses = 0; presses < 40; presses += 1) {
    await page.keyboard.press('Tab');
    if (await trigger.evaluate((element) => element === document.activeElement)) {
      break;
    }
  }
  await expect(trigger).toBeFocused();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText('Primary criterion')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test('design mock: mobile shows Contexa and the context lookup rule first and folds the rest', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/design?lng=en');
  await expect(page.getByRole('heading', { name: 'Contexa' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Business record rule' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Perimeter (WAF)' })).toBeHidden();
  await page.getByRole('button', { name: /Show 3 more/ }).click();
  await expect(page.getByRole('heading', { name: 'Perimeter (WAF)' })).toBeVisible();
});
