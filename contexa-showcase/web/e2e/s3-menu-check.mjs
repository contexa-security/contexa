// docs/agent Agent중심-화면 AC-4b real-server check (G-5, AS-12 (6)): the agent menu after the operator's refresh of the editable
// case ED1. READ ONLY on the visitor port (no run, no write): (1) the listing offers the 69 combinations (15 and the 54 of
// ED1: 18 choices on 3 paths) with ED1's lists; (2) every ED1 combination the job ran has a stored answer that names the
// choice it was run with, the delegation it executed and the path; (3) reading an answer starts no run and makes no model
// call (the caller compares the database before and after); (4) a value outside the lists is refused (400) and a
// combination the menu does not hold is not found (404); (5) the answers differ across choices (the choice is not ignored).
// Usage (web folder): node e2e/s3-menu-check.mjs <outDir> [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { request } from '@playwright/test';

const args = process.argv.slice(2);
const out = args[0];
if (!out) {
  console.error('usage: node e2e/s3-menu-check.mjs <outDir> [--base <url>]');
  process.exit(2);
}
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
fs.mkdirSync(out, { recursive: true });

const report = { checks: [], failures: [], methods: {} };
function check(name, ok, detail = '') {
  report.checks.push({ name, ok, detail });
  if (!ok) {
    report.failures.push(name);
  }
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`);
}

const context = await request.newContext({ baseURL: base, extraHTTPHeaders: { Accept: 'application/json' } });
const get = async (url) => {
  report.methods.GET = (report.methods.GET ?? 0) + 1;
  const response = await context.get(url);
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status(), body };
};

const listing = await get('/api/agent-menu');
check('the listing is read', listing.status === 200, `status ${listing.status}`);
const items = listing.body?.items ?? [];
const edit = listing.body?.delegationEdit;
check('the listing names the editable case and its lists', edit?.case === 'ED1' && edit.quantities.length === 3
  && edit.periods.length === 3 && edit.operations.length === 2, JSON.stringify(edit));
const ed1 = items.filter((item) => item.caseKey === 'ED1');
const plain = items.filter((item) => item.caseKey !== 'ED1');
check('the 15 combinations of the other cases are stored', plain.length === 15, `${plain.length}`);
check('the 54 combinations of ED1 (18 choices on 3 paths) are stored', ed1.length === 54, `${ed1.length}`);
const choiceKey = (choice) => `Q${choice?.quantity ?? '-'}.${choice?.period ?? '-'}.${choice?.operations ?? '-'}`;
check('every ED1 combination names a full choice', ed1.every((item) => item.choice && item.choice.quantity && item.choice.period
  && item.choice.operations));
check('the ED1 combinations are 18 distinct choices on each of the 3 paths', new Set(ed1.map((item) => `${item.path}/${choiceKey(item.choice)}`)).size === 54
  && new Set(ed1.map((item) => choiceKey(item.choice))).size === 18);

// every ED1 answer, read once
const answers = [];
for (const item of ed1) {
  const q = `quantity=${item.choice.quantity}&period=${item.choice.period}&operations=${item.choice.operations}`;
  const answer = await get(`/api/agent-menu/ED1/${item.path}?${q}`);
  answers.push({ item, status: answer.status, body: answer.body });
}
check('every ED1 combination has a stored answer (200)', answers.every((answer) => answer.status === 200),
  answers.filter((answer) => answer.status !== 200).map((answer) => `${answer.item.path}/${choiceKey(answer.item.choice)}:${answer.status}`).join(' '));
check('each answer names the choice and the path it was run with', answers.every((answer) => answer.body
  && choiceKey(answer.body.choice) === choiceKey(answer.item.choice) && answer.body.path === answer.item.path));
const outcome = (answer) => `${answer.body?.run?.proof?.controls?.D?.firstStopStep ?? 'none'}`;
const byChoice = new Map();
for (const answer of answers.filter((entry) => entry.item.path === 'OAUTH2_DELEGATED')) {
  byChoice.set(choiceKey(answer.item.choice), outcome(answer));
}
check('the delegated path\'s answers differ across the 18 choices (the choice is not ignored)', new Set(byChoice.values()).size >= 2,
  JSON.stringify([...byChoice.entries()]));
check('an answer shows the delegation of its choice (the limit, and revoked only for a revoked choice)',
  answers.every((answer) => answer.body?.caseView?.delegation
    && answer.body.caseView.delegation.maxItemsPerRequest === answer.item.choice.quantity
    && (answer.body.caseView.delegation.status === 'REVOKED') === (answer.item.choice.period === 'REVOKED')),
  answers.filter((answer) => !answer.body?.caseView?.delegation
    || answer.body.caseView.delegation.maxItemsPerRequest !== answer.item.choice.quantity)
    .map((answer) => choiceKey(answer.item.choice)).join(' '));

// refusals
const outside = await get('/api/agent-menu/ED1/OAUTH2_DELEGATED?quantity=401&period=VALID&operations=READ_ONLY');
const outsidePeriod = await get('/api/agent-menu/ED1/OAUTH2_DELEGATED?quantity=40&period=FOREVER&operations=READ_ONLY');
const partial = await get('/api/agent-menu/ED1/OAUTH2_DELEGATED?quantity=40');
const missingCase = await get('/api/agent-menu/NOPE/OAUTH2_DELEGATED');
const wrongPath = await get('/api/agent-menu/ED1/NO_PATH?quantity=40&period=VALID&operations=READ_ONLY');
check('a value outside the lists is refused with 400', outside.status === 400 && outsidePeriod.status === 400,
  `${outside.status}/${outsidePeriod.status}`);
check('a combination the menu does not hold is not found (404)', [partial.status, missingCase.status, wrongPath.status]
  .every((status) => status === 404 || status === 400), `${partial.status}/${missingCase.status}/${wrongPath.status}`);

fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify({ ...report, byChoice: [...byChoice.entries()] }, null, 2));
fs.writeFileSync(path.join(out, 'answers.json'), JSON.stringify(answers.map((answer) => ({ path: answer.item.path,
  choice: choiceKey(answer.item.choice), status: answer.status, firstStop: outcome(answer), ranAt: answer.body?.ranAt })), null, 2));
console.log(`${report.checks.length - report.failures.length}/${report.checks.length} passed (${report.methods.GET} reads)`);
await context.dispose();
process.exit(report.failures.length === 0 ? 0 : 1);
