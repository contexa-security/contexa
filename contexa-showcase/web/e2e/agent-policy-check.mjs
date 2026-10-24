// docs/agent RW-3 (A1-9): a policy that uses the agent conditions is evaluated by control D as written, and the
// policies without them give what they gave before. Through an ops console session the operator adds, on control D's
// policy screen, a policy above the documents rule that lets the same roles list documents, an agent only with its
// accountable person's confirmation (the screen refuses a DENY policy on a target an ALLOW policy holds, so the
// requirement is written as an ALLOW policy's condition). Real business agent runs then show it: N1 (an agent within
// its delegation) is refused the documents list; T5 gets the request its delegating person approved through; the
// person's own same request (T5 REPORT) goes through. The policy is deleted on the policy screen and N1 runs again as
// before.
// Every run calls the agent's model and control D's decision models (luna; a natural ESCALATE may reach sol).
// Cost: besides the runs, control D analyses the administrator's console requests as any user's and may reach its
// Layer 2 model for a new administrator. Run it when needed.
// Usage (web folder): node e2e/agent-policy-check.mjs <output folder> [ops url] [--policy-only]
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';
import { closeSession, openSession, signIn } from './consoleSession.mjs';

const out = process.argv[2];
// --policy-only adds and deletes the policy without the runs (a check of the screens alone).
const policyOnly = process.argv.includes('--policy-only');
const ops = (process.argv.slice(3).find((argument) => !argument.startsWith('--')) ?? 'http://127.0.0.1:19190')
  .replace(/[/]+$/, '');
if (!out) {
  console.error('usage: node e2e/agent-policy-check.mjs <output folder> [ops url]');
  process.exit(2);
}
fs.mkdirSync(out, { recursive: true });

/** The documents rule's own roles (SC_RBAC_DOCUMENT_LIST), and for an agent its accountable person's confirmation. */
const CONDITION = "hasAnyAuthority('ROLE_SC_ADMIN','ROLE_SC_ENGINEER','ROLE_SC_PARTNER','ROLE_SC_PM','SCOPE_sc.admin',"
  + "'SCOPE_sc.engineer','SCOPE_sc.partner','SCOPE_sc.pm') and (!isAgent() or agentRequestConfirmed())";
const TARGET = '/api/projects/*/documents';
const report = { checks: [], failures: [], runs: {} };

function check(name, ok, detail) {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

/** Runs an agent task through the ops port and answers its summary. */
async function runTask(key, query = '') {
  const job = await (await fetch(`${ops}/ops/agent-tasks/${key}${query}`, { method: 'POST' })).json();
  let status = job.status;
  let result = job;
  while (status === 'QUEUED' || status === 'RUNNING') {
    await new Promise((resolve) => setTimeout(resolve, 3000));
    result = await (await fetch(`${ops}/ops/jobs/${job.jobId}`)).json();
    status = result.status;
  }
  const runId = result.results?.[0]?.runId;
  if (!runId) {
    throw new Error(`${key}${query}: no run (${status})`);
  }
  return (await fetch(`${ops}/ops/agent-tasks/runs/${runId}`)).json();
}

/** Control D's answers to the documents list requests of a run's agent work. */
function documentsAnswers(summary) {
  return (summary.steps ?? []).filter((step) => (step.path ?? '').includes('/documents'))
    .map((step) => ({ step: step.stepNo, D: step.outcomes?.D, A: step.outcomes?.A }));
}

async function addPolicy(page, session, name) {
  await page.goto(`${session.console}/contexa/admin/policies/register?lang=ko`);
  await page.fill('[name="name"]', name);
  await page.fill('[name="description"]', 'RW-3 check: an agent request needs its accountable person confirmation');
  await page.selectOption('[name="effect"]', 'ALLOW');
  await page.fill('[name="priority"]', '150');
  await page.selectOption('[name="targets[0].targetType"]', 'URL');
  await page.fill('[name="targets[0].targetIdentifier"]', TARGET);
  await page.selectOption('[name="targets[0].httpMethod"]', 'GET');
  await page.fill('[name="rules[0].description"]', "The documents roles; an agent with its person's confirmation");
  // A new rule has no condition until the operator adds one with the rule's own button.
  if ((await page.locator('[name="rules[0].conditions[0].expression"]').count()) === 0) {
    await page.locator('button[onclick="addCondition(this)"]').first().click();
  }
  await page.fill('[name="rules[0].conditions[0].expression"]', CONDITION);
  const phase = page.locator('[name="rules[0].conditions[0].authorizationPhase"]');
  if ((await phase.count()) > 0) {
    await phase.selectOption('PRE_AUTHORIZE');
  }
  const reason = page.locator('[name="changeReason"]');
  if ((await reason.count()) > 0) {
    await reason.fill('RW-3 check of the agent conditions');
  }
  await page.locator('button[type=submit].modern-btn-primary').first().click();
  // The screen validates first; a policy that overlaps others (this one overlaps the documents rule on purpose) is
  // shown in a window the operator confirms.
  const proceed = page.locator('#validation-proceed-btn');
  const modal = page.locator('#validation-result-modal');
  for (let waited = 0; !/policy-center/.test(page.url()); waited += 500) {
    if (waited > 20000) {
      throw new Error('the policy screen neither saved nor asked');
    }
    if (await proceed.isVisible()) {
      report.validation = await page.locator('#validation-result-content').innerText();
      await page.screenshot({ path: path.join(out, 'policy-validation.png'), fullPage: true });
      await proceed.click();
      await page.waitForURL(/policy-center/, { timeout: 20000 });
      break;
    }
    if (await modal.isVisible()) {
      throw new Error(`the policy screen refused: ${await page.locator('#validation-result-content').innerText()}`);
    }
    await page.waitForTimeout(500);
  }
  await page.goto(`${session.console}/contexa/admin/policy-center?tab=list&lang=ko`);
  await page.screenshot({ path: path.join(out, 'policy-added.png'), fullPage: true });
  return page.locator('tr', { hasText: name });
}

async function deletePolicy(page, session, name) {
  await page.goto(`${session.console}/contexa/admin/policy-center?tab=list&lang=ko`);
  const row = page.locator('tr', { hasText: name });
  if ((await row.count()) === 0) {
    return false;
  }
  await row.first().locator('button', { has: page.locator('i.fa-trash') }).click();
  await page.fill('#delete-reason-input', 'RW-3 check finished');
  await page.locator('#delete-reason-modal button', { has: page.locator('i.fa-trash') }).last().click();
  await page.waitForLoadState('networkidle');
  await page.goto(`${session.console}/contexa/admin/policy-center?tab=list&lang=ko`);
  return (await page.locator('tr', { hasText: name }).count()) === 0;
}

async function main() {
  const session = await openSession(ops);
  const name = `RW3-AGENT-CONFIRMATION-${session.key}`;
  const browser = await chromium.launch();
  let added = false;
  try {
    const page = await (await browser.newContext({ locale: 'ko-KR', viewport: { width: 1440, height: 900 } }))
      .newPage();
    await signIn(page, ops, session);
    const row = await addPolicy(page, session, name);
    added = (await row.count()) === 1;
    check('the policy is added on control D\'s policy screen', added);
    if (!added || policyOnly) {
      if (added) {
        const deleted = await deletePolicy(page, session, name);
        added = !deleted;
        check('the policy is deleted on the policy screen', deleted);
      }
      return;
    }

    const within = await runTask('N1');
    report.runs.N1withPolicy = within.runId;
    const withinDocuments = documentsAnswers(within);
    check('N1 with the policy: the agent is refused the documents list at control D',
      withinDocuments.length > 0 && withinDocuments.every((answer) => answer.D?.outcome === 'REFUSED'),
      JSON.stringify(withinDocuments));
    check('N1 with the policy: the plain controls still deliver it',
      withinDocuments.every((answer) => answer.A?.outcome === 'DELIVERED'));

    const approved = await runTask('T5', '?delegator=APPROVE');
    report.runs.T5approve = approved.runId;
    const resend = approved.confirmation?.resend;
    check('T5 with the policy: the request its person approved goes through', resend?.httpStatus === 200,
      `HTTP ${resend?.httpStatus} ${resend?.ruleId ?? ''}`);

    const reported = await runTask('T5', '?delegator=REPORT');
    report.runs.T5report = reported.runId;
    const person = reported.confirmation?.personRequest;
    check('T5 with the policy: the person\'s own same request goes through', person?.httpStatus === 200,
      `HTTP ${person?.httpStatus} ${person?.ruleId ?? ''}`);

    const deleted = await deletePolicy(page, session, name);
    added = !deleted;
    check('the policy is deleted on the policy screen', deleted);

    const after = await runTask('N1');
    report.runs.N1after = after.runId;
    const afterDocuments = documentsAnswers(after);
    check('N1 after the policy: control D answers the documents list as before',
      afterDocuments.length > 0 && afterDocuments.every((answer) => answer.D?.outcome === 'DELIVERED'),
      JSON.stringify(afterDocuments));
  } catch (error) {
    check('the check ran to its end', false, String(error));
  } finally {
    if (added) {
      const page = await (await browser.newContext()).newPage();
      try {
        await signIn(page, ops, session);
        check('the policy left by a failure is deleted', await deletePolicy(page, session, name));
      } catch (error) {
        check('the policy left by a failure is deleted', false, String(error));
      }
    }
    await browser.close();
    const closed = await closeSession(ops, session);
    check('the console session is closed', closed === 204, `HTTP ${closed}`);
    fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  }
  console.log(`done ${report.checks.length} checks, ${report.failures.length} failing`);
  process.exitCode = report.failures.length === 0 ? 0 : 1;
}

await main();
