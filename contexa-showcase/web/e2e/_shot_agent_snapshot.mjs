// Development helper: opens an agent screen of the dev server with the case and the run answered from a frozen
// snapshot (showcase-portal/src/main/resources/agent-runs/<label>.json), so a screen can be looked at without a live
// run. Usage: node e2e/_shot_agent_snapshot.mjs <path> <language> <width> <out.png> [snapshot label]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

const here = path.dirname(fileURLToPath(import.meta.url));
const [route, language, width, out, label = 'T5-confirm-approve'] = process.argv.slice(2);
const snapshot = JSON.parse(
  fs.readFileSync(
    path.join(here, '..', '..', 'showcase-portal', 'src', 'main', 'resources', 'agent-runs', `${label}.json`),
    'utf8',
  ),
);
const caseView = { ...snapshot.case, recorded: { runId: snapshot.runId, startedAt: snapshot.run.startedAt } };
const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: Number(width), height: 900 },
  locale: language,
  reducedMotion: 'reduce',
});
const page = await context.newPage();
await page.route('**/api/agent-cases/T5', (r) => r.fulfill({ json: caseView }));
await page.route(`**/api/runs/${snapshot.runId}/agent`, (r) => r.fulfill({ json: snapshot.run }));
await page.goto(`http://localhost:5180${route}?lng=${language}`, { waitUntil: 'networkidle' });
await page.waitForTimeout(800);
await page.screenshot({ path: out, fullPage: true });
await browser.close();
console.log('saved', out);
