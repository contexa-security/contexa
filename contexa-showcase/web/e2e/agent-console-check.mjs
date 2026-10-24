// docs/agent RW-2 (A1-6): the agent registry screens of control D's admin console in a real browser, as an operator
// uses them. An ops console session gives a security administrator of control D; the browser signs in through control
// D's own sign-in (password, then the one-time code the demo inbox received), registers an agent, reads it in the list
// and the detail screen in Korean and English at 1440 and 390, transfers its sponsor and deregisters it, then removes
// it and closes the session. Each screen: its values, no serious or critical axe violation, no sideways scroll, and the
// detail screen reached from the list with the keyboard.
// Cost: control D analyses the administrator's console requests as any user's; a new administrator's first requests
// can reach the Layer 2 model (2026-10-24: three sessions gave 9 decisions, 8 of them Layer 2). Run it when needed.
// Usage (web folder): node e2e/agent-console-check.mjs <output folder> [ops url]
import fs from 'node:fs';
import path from 'node:path';
import AxeBuilder from '@axe-core/playwright';
import { chromium } from '@playwright/test';
import { closeSession, openSession, signIn } from './consoleSession.mjs';

const out = process.argv[2];
const ops = (process.argv[3] ?? 'http://127.0.0.1:19190').replace(/[/]+$/, '');
if (!out) {
  console.error('usage: node e2e/agent-console-check.mjs <output folder> [ops url]');
  process.exit(2);
}
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [] };

function check(name, ok, detail) {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

async function screen(page, name, width) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  const axe = await new AxeBuilder({ page }).include('main').analyze();
  const serious = axe.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => `${violation.id} (${violation.nodes.length})`);
  await page.screenshot({ path: path.join(out, `${name}-${width}.png`), fullPage: true });
  check(`${name} ${width} no sideways scroll`, overflow <= 1, `overflow ${overflow}px`);
  check(`${name} ${width} axe serious/critical none`, serious.length === 0, serious.join(', '));
}

async function main() {
  const session = await openSession(ops);
  const agentId = `console-check-${session.key}`;
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await signIn(page, ops, session);
    check('sign-in through control D (password, one-time code)', page.url().includes(session.console));

    // Register an agent as an operator does (A1-6: registry and sponsor).
    await page.goto(`${session.console}/contexa/admin/agents/new?lang=ko`);
    await page.fill('#agentId', agentId);
    await page.fill('#displayName', 'Console check agent');
    await page.fill('#agentType', 'REPORTING');
    await page.fill('#sponsorId', session.username);
    await page.locator('#agentRegisterForm button[type=submit]').click();
    await page.waitForLoadState('networkidle');
    check('the registration is taken', !page.url().endsWith('/agents/new'), page.url());

    const list = `${session.console}/contexa/admin/agents?filter=all&keyword=${encodeURIComponent(agentId)}`;
    for (const [language, width] of [['ko', 1440], ['en', 1440], ['ko', 390], ['en', 390]]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
      await page.goto(`${list}&lang=${language}`);
      const row = page.locator('tr', { hasText: agentId });
      check(`list ${language} ${width} shows the agent`, (await row.count()) === 1);
      check(`list ${language} ${width} shows its sponsor`, (await row.first().innerText()).includes(session.username));
      await screen(page, `list-${language}`, width);
      if (width === 1440) {
        // The detail screen is reached from the list with the keyboard alone.
        const detail = row.first().locator('a[href*="/agents/detail"]');
        let reached = false;
        for (let presses = 0; presses < 80 && !reached; presses += 1) {
          await page.keyboard.press('Tab');
          reached = await detail.evaluate((element) => element === document.activeElement);
        }
        check(`list ${language} detail link reached with Tab`, reached);
        if (reached) {
          await page.keyboard.press('Enter');
          await page.waitForURL(/agents\/detail/);
        }
      } else {
        await page.goto(`${session.console}/contexa/admin/agents/detail?agentId=${encodeURIComponent(agentId)}`
          + `&lang=${language}`);
      }
      const body = await page.locator('main').innerText();
      check(`detail ${language} ${width} shows the agent and its sponsor`,
        body.includes(agentId) && body.includes(session.username));
      await screen(page, `detail-${language}`, width);
    }

    // Lifecycle (A1-6): the sponsor is transferred, then the agent is deregistered and removed.
    await page.setViewportSize({ width: 1440, height: 900 });
    const detailUrl = `${session.console}/contexa/admin/agents/detail?agentId=${encodeURIComponent(agentId)}&lang=ko`;
    await page.goto(detailUrl);
    const sponsorForm = page.locator('form[action*="/manage/sponsor"]');
    await sponsorForm.locator('input[name=sponsorId]').fill('it-admin-2');
    const reason = sponsorForm.locator('[name=reason]');
    if ((await reason.count()) > 0) {
      await reason.fill('Console check: sponsor transfer');
    }
    await sponsorForm.locator('button[type=submit]').click();
    await page.waitForLoadState('networkidle');
    await page.goto(detailUrl);
    check('the sponsor transfer is shown', (await page.locator('main').innerText()).includes('it-admin-2'));

    page.on('dialog', (dialog) => dialog.accept());
    const deregister = page.locator('form[action*="/manage/deregister"]');
    const deregisterReason = deregister.locator('[name=reason]');
    if ((await deregisterReason.count()) > 0) {
      await deregisterReason.fill('Console check: deregistered');
    }
    await deregister.locator('button[type=submit]').click();
    await page.waitForLoadState('networkidle');
    await page.goto(detailUrl);
    await page.screenshot({ path: path.join(out, 'detail-deregistered-1440.png'), fullPage: true });
    check('the deregistration is shown', (await page.locator('main').innerText()).includes('등록 해제'));

    const remove = page.locator('form[action*="/manage/remove"]');
    if ((await remove.count()) > 0) {
      const removeReason = remove.locator('[name=reason]');
      if ((await removeReason.count()) > 0) {
        await removeReason.fill('Console check: removed');
      }
      await remove.locator('button[type=submit]').click();
      await page.waitForLoadState('networkidle');
    }
    await page.goto(`${list}&lang=ko`);
    check('the removed agent is gone from the list',
      (await page.locator('tr', { hasText: agentId }).count()) === 0);
  } catch (error) {
    check('the check ran to its end', false, String(error));
  } finally {
    await browser.close();
    const closed = await closeSession(ops, session);
    check('the console session is closed', closed === 204, `HTTP ${closed}`);
    fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  }
  console.log(`done ${report.checks.length} checks, ${report.failures.length} failing`);
  process.exitCode = report.failures.length === 0 ? 0 : 1;
}

await main();
