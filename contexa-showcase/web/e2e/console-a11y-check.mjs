// docs/agent BF (F-8): the admin console's shared header and the screens the agent check found wanting (users,
// blacklist, security monitor) in a real browser: no sideways scroll at 390 and 1440, no serious or critical axe
// violation in the header and the body, the header's width, and the old policy list address leading to the policy
// center. Each violation is saved with its elements, so a fix can be aimed at them.
// Cost: control D analyses the administrator's console requests as any user's; a new administrator's first requests
// can reach the Layer 2 model. --keep leaves the session open and saves it, and --session <file> uses a saved one
// (within its 30 minutes), so the checks before and after a fix share one administrator. Run it when needed.
// --screens a,b limits the screens (names below) and --widths 390 the widths, to keep the administrator's requests few.
// Usage (web folder): node e2e/console-a11y-check.mjs <output folder> [ops url] [--keep] [--session <file>]
//   [--screens <names>] [--widths <numbers>]
import fs from 'node:fs';
import path from 'node:path';
import AxeBuilder from '@axe-core/playwright';
import { chromium } from '@playwright/test';
import { closeSession, openSession, signIn } from './consoleSession.mjs';

const args = process.argv.slice(2);
const out = args[0];
const keep = args.includes('--keep');
const sessionFile = args.includes('--session') ? args[args.indexOf('--session') + 1] : null;
const option = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : null);
const only = option('--screens')?.split(',');
const widths = option('--widths')?.split(',').map(Number) ?? [1440, 390];
const ops = (
  args
    .slice(1)
    .find((argument, index, all) => !argument.startsWith('--') && !all[index - 1]?.startsWith('--')) ??
  'http://127.0.0.1:19190'
).replace(/[/]+$/, '');
if (!out) {
  console.error(
    'usage: node e2e/console-a11y-check.mjs <output folder> [ops url] [--keep] [--session <file>]',
  );
  process.exit(2);
}
fs.mkdirSync(out, { recursive: true });

const SCREENS = [
  ['users', '/contexa/admin/users'],
  ['blacklist', '/contexa/admin/blacklist'],
  ['security-monitor', '/contexa/admin/security-monitor'],
  ['agents', '/contexa/admin/agents'],
  ['groups', '/contexa/admin/groups'],
  ['permissions', '/contexa/admin/permissions'],
  ['roles', '/contexa/admin/roles'],
  ['role-hierarchies', '/contexa/admin/role-hierarchies'],
  ['ip-management', '/contexa/admin/ip-management'],
  ['company-records', '/contexa/admin/company-records'],
  ['menu-management', '/contexa/admin/menu-management'],
  ['session-management', '/contexa/admin/session-management'],
  ['policy-list', '/contexa/admin/policy-center?tab=list'],
  ['policy-resources', '/contexa/admin/policy-center?tab=resources'],
  ['agent-stops', '/contexa/admin/blacklist/agents'],
].filter(([name]) => !only || only.includes(name));
const report = { checks: [], failures: [], violations: {} };

function check(name, ok, detail) {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

async function screen(page, session, name, address, width) {
  await page.setViewportSize({ width, height: 900 });
  await page.goto(`${session.console}${address}${address.includes('?') ? '&' : '?'}lang=ko`);
  await page.waitForLoadState('networkidle');
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  const header = await page.evaluate(() => {
    const bar = document.querySelector('header');
    return bar ? Math.round(bar.scrollWidth) : null;
  });
  const axe = await new AxeBuilder({ page }).analyze();
  const serious = axe.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact));
  report.violations[`${name}-${width}`] = serious.map((violation) => ({
    id: violation.id,
    count: violation.nodes.length,
    nodes: violation.nodes.slice(0, 8).map((node) => ({
      target: node.target.join(' '),
      html: node.html.slice(0, 240),
      summary: (node.failureSummary ?? '').slice(0, 300),
    })),
  }));
  await page.screenshot({ path: path.join(out, `${name}-${width}.png`), fullPage: false });
  check(`${name} ${width} no sideways scroll`, overflow <= 1, `overflow ${overflow}px, header ${header}px`);
  check(
    `${name} ${width} axe serious/critical none`,
    serious.length === 0,
    serious.map((violation) => `${violation.id}(${violation.nodes.length})`).join(', '),
  );
}

async function main() {
  const session = sessionFile ? JSON.parse(fs.readFileSync(sessionFile, 'utf-8')) : await openSession(ops);
  if (keep) {
    fs.writeFileSync(path.join(out, 'session.json'), JSON.stringify(session));
  }
  const browser = await chromium.launch();
  try {
    const page = await (
      await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 900 } })
    ).newPage();
    await signIn(page, ops, session);
    for (const [name, address] of SCREENS) {
      for (const width of widths) {
        await screen(page, session, name, address, width);
      }
    }
    const answer = await page.goto(`${session.console}/contexa/admin/policies?lang=ko`);
    check(
      'the old policy list address leads to the policy center list',
      answer?.status() === 200 && /\/contexa\/admin\/policy-center\?tab=list/.test(page.url()),
      `HTTP ${answer?.status()} ${page.url()}`,
    );
  } catch (error) {
    check('the check ran to its end', false, String(error));
  } finally {
    await browser.close();
    if (!keep) {
      const closed = await closeSession(ops, session);
      check('the console session is closed', closed === 204, `HTTP ${closed}`);
    }
    fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  }
  console.log(`done ${report.checks.length} checks, ${report.failures.length} failing`);
  process.exitCode = report.failures.length === 0 ? 0 : 1;
}

await main();
