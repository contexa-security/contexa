// The general recorder of the guide videos (가이드영상-제작기획안.md 7.1절): records the real site at 1440 x 900 following a
// scenario file, draws the overlay (overlay.mjs), gives every scene the time its captions need in the language, and writes
// the video, the two caption files (wide and phone) and the manifest entry. With `dry` it goes through the same scenes
// without a video or a pause and returns only what each screen showed, which is what guide-verify.mjs compares.
import { chromium } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LINE_LIMIT, LINE_LIMIT_NARROW, vtt } from '../guideCaptions.mjs';
import { fingerprintOf } from './fingerprint.mjs';
import { installOverlay, OVERLAY_CSS } from './overlay.mjs';
import { loadScenarios, sceneDurations, selectorProblems, validate } from './scenario.mjs';

const SIZE = { width: 1440, height: 900 };
const SCENARIOS = 'guides/scenarios';
const dictionaries = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};

/** The scenario of a guide id, checked; throws what it lacks. */
export function scenarioOf(id) {
  const scenario = loadScenarios(SCENARIOS).find((found) => found.id === id);
  if (!scenario) throw new Error(`no scenario for "${id}" in ${SCENARIOS}`);
  const problems = [
    ...validate(scenario),
    ...scenario.scenes.flatMap((scene, index) =>
      [scene.focus, scene.point, scene.click, scene.wait].filter(Boolean).flatMap((selector) =>
        selectorProblems(selector).map((problem) => `${id} scene ${index + 1}: ${selector}: ${problem}`),
      ),
    ),
  ];
  if (problems.length > 0) throw new Error(problems.join('\n'));
  return scenario;
}

/** The screens' version: the commit the web folder is at, with a plus when it has changes not committed yet. */
export function buildId() {
  try {
    const hash = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf-8' }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain', '--', '.'], { encoding: 'utf-8' }).trim() !== '';
    return dirty ? `${hash}+` : hash;
  } catch {
    return 'dev';
  }
}

function format(text, values) {
  return text.replace(/\{\{(\w+)\}\}/g, (_, name) => String(values[name] ?? ''));
}

async function box(page, selector, scene, what) {
  const locator = page.locator(selector).first();
  try {
    await locator.waitFor({ state: 'visible', timeout: 15_000 });
  } catch {
    throw new Error(`scene ${scene}: ${what} ${selector} is not on the screen (the screen changed: fix the anchor or the scenario)`);
  }
  await locator.scrollIntoViewIfNeeded();
  const found = await locator.boundingBox();
  if (!found) throw new Error(`scene ${scene}: ${what} ${selector} has no box`);
  return found;
}

/**
 * Records (or, with `dry`, only observes) a guide in a language. Returns the scenes with the second each began, the second
 * the last one ended, the length, what each scene's screen showed and the fingerprint of all of it.
 */
export async function recordGuide({ id, language, base, out, dry = false }) {
  const scenario = scenarioOf(id);
  const dictionary = dictionaries[language];
  const durations = sceneDurations(scenario, dictionary, language);
  const browser = await chromium.launch();
  const folder = mkdtempSync(join(tmpdir(), 'guide-'));
  const context = await browser.newContext({
    viewport: SIZE,
    locale: language,
    reducedMotion: 'reduce',
    ...(dry ? {} : { recordVideo: { dir: folder, size: SIZE } }),
  });
  const started = Date.now();
  const page = await context.newPage();
  if (!dry) await page.addInitScript(installOverlay, OVERLAY_CSS);
  const at = () => (Date.now() - started) / 1000;
  const scenes = [];
  const observed = [];
  try {
    await page.goto(`${base}${scenario.path}?lng=${language}`, { waitUntil: 'networkidle' });
    await page.locator('main h1').first().waitFor({ timeout: 15_000 });
    await page.waitForTimeout(dry ? 200 : 1200);
    for (const [index, scene] of scenario.scenes.entries()) {
      const number = index + 1;
      if (scene.path && new URL(page.url()).pathname !== scene.path) {
        await page.goto(`${base}${scene.path}?lng=${language}`, { waitUntil: 'networkidle' });
      }
      if (scene.wait) await box(page, scene.wait, number, 'wait target');
      const focus = await box(page, scene.focus, number, 'focus');
      const point = scene.point ? await box(page, scene.point, number, 'point') : focus;
      const badges = [];
      for (const badge of scene.badges ?? []) {
        const target = await box(page, badge.target, number, 'badge target');
        badges.push({ n: badge.n, x: target.x, y: target.y });
      }
      const labels = [];
      for (const label of scene.labels ?? []) {
        const target = await box(page, label.target, number, 'label target');
        labels.push({ text: dictionary[label.key], x: target.x, y: Math.max(8, target.y - 44) });
      }
      observed.push(
        await page.evaluate(
          ({ focusSelector, selectors }) => ({
            path: location.pathname,
            title: document.querySelector('main h1')?.textContent ?? '',
            focus: document.querySelector(focusSelector)?.textContent ?? '',
            anchors: selectors.filter((selector) => document.querySelector(selector)),
          }),
          {
            focusSelector: scene.focus,
            selectors: [scene.focus, scene.point, scene.click, scene.wait, ...(scene.badges ?? []).map((b) => b.target), ...(scene.labels ?? []).map((l) => l.target)].filter(Boolean),
          },
        ),
      );
      if (dry) {
        if (scene.click) await page.locator(scene.click).first().click();
        if (scene.click) await page.waitForLoadState('networkidle').catch(() => undefined);
        continue;
      }
      const sceneStart = Date.now();
      await page.evaluate((shown) => window.__guide.show(shown), { focus, badges, labels });
      scenes.push({ key: scene.key, start: Math.round(at() * 1000) / 1000 });
      if (scene.point || scene.click) {
        await page.mouse.move(point.x + point.width / 2, point.y + point.height / 2, { steps: 18 });
      }
      await page.waitForTimeout(Math.max(0, durations[index] * 1000 - (Date.now() - sceneStart)));
      if (scene.click) {
        await page.locator(scene.click).first().click();
        await page.waitForLoadState('networkidle').catch(() => undefined);
        await page.waitForTimeout(700);
      }
      await page.evaluate(() => window.__guide?.clear());
    }
    const end = Math.round(at() * 1000) / 1000;
    const fingerprint = fingerprintOf({ scenario, dictionary, observed, language });
    if (dry) {
      return { scenes, end, durationSec: 0, observed, fingerprint, file: null };
    }
    const date = new Date().toISOString().slice(0, 10);
    const screens = buildId();
    await page.evaluate((text) => window.__guide.stamp(text), format(dictionary['guide.recorded'], { date, screens }));
    await page.waitForTimeout(1300);
    const durationSec = Math.round(at() * 10) / 10;
    const video = page.video();
    await context.close();
    mkdirSync(out, { recursive: true });
    const file = `${id}.${language}.webm`;
    copyFileSync(await video.path(), join(out, file));
    const wide = `${id}.${language}.vtt`;
    const narrow = `${id}.${language}.m.vtt`;
    writeFileSync(join(out, wide), vtt(scenes, end, dictionary, LINE_LIMIT[language]));
    writeFileSync(join(out, narrow), vtt(scenes, end, dictionary, LINE_LIMIT_NARROW[language]));
    const entry = {
      file,
      captions: { [language]: wide },
      captionsNarrow: { [language]: narrow },
      durationSec,
      recordedAt: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
      screens,
      scenes,
      end,
      fingerprint,
      observed,
    };
    updateManifest(out, id, language, entry);
    return { scenes, end, durationSec, observed, fingerprint, file };
  } finally {
    await context.close().catch(() => undefined);
    await browser.close();
  }
}

/** Puts a recording into the manifest next to the videos: `id -> language -> video`; an old single entry is replaced. */
export function updateManifest(out, id, language, entry) {
  const path = join(out, 'guides.json');
  const manifest = existsSync(path) ? JSON.parse(readFileSync(path, 'utf-8')) : {};
  const current = manifest[id] && !('file' in manifest[id]) ? manifest[id] : {};
  manifest[id] = { ...current, [language]: entry };
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
}
