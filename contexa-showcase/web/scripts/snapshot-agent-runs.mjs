// docs/agent Agent중심-화면 AS-0: freezes the reference agent runs the screens and their tests lean on, as files, so that a
// cleanup of the portal database cannot break a screen. Each snapshot is the portal's own answer for the run
// (/api/runs/{runId}/agent) and for its case (/api/agent-cases/{key}), read from a running portal; nothing is computed here.
// The selection (run id, case, path, flights, why) is the table below and the plan's baseline document.
// Usage: node scripts/snapshot-agent-runs.mjs [--base http://127.0.0.1:19180]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const baseAt = args.indexOf('--base');
const base = baseAt >= 0 ? args[baseAt + 1] : 'http://127.0.0.1:19180';
const outDir = path.join(here, '..', '..', 'showcase-portal', 'src', 'main', 'resources', 'agent-runs');

/** label: file name; why: the selection reason; kind: DELEGATED / AUTONOMOUS / SESSION / BURST_ON / BURST_OFF / CONFIRM. */
const REFERENCE = [
  { label: 'T5-confirm-approve', runId: 'run-d2ca817d4929', caseKey: 'T5', kind: 'DELEGATED',
    why: 'main case of the agent group; the delegating employee approved the confirmation (APPROVE, DELEGATION_ENDED)' },
  { label: 'T5-confirm-report', runId: 'run-f440d9283e17', caseKey: 'T5', kind: 'DELEGATED',
    why: 'the same case with the agent reported (REPORT) instead of approved' },
  { label: 'M19A-delegated', runId: 'run-f95da22d28e7', caseKey: 'M19A', kind: 'DELEGATED',
    why: 'path 1 of 3: the agent acting for a person (token exchange); the export over the declared daily amount' },
  { label: 'M19A-autonomous', runId: 'run-e307f5472e7f', caseKey: 'M19A', kind: 'AUTONOMOUS',
    why: 'path 2 of 3: the agent on its own client credentials' },
  { label: 'M19A-session', runId: 'run-6a7d52a0735f', caseKey: 'M19A', kind: 'SESSION',
    why: 'path 3 of 3: the agent signed in with its own account' },
  { label: 'M41A-flights-on', runId: 'run-30b46eefc46b', caseKey: 'M41A', kind: 'BURST_ON',
    why: '60 identical list requests with the flights on: one analysis, 66 of 66 delivered (production models, final build)' },
  { label: 'M41A-flights-off', runId: 'run-98a800a4929b', caseKey: 'M41A', kind: 'BURST_OFF',
    why: 'the same burst with the flights off: every request analysed (66 decisions, 61 at once)' },
  { label: 'M41T-flights-on', runId: 'run-edfb8ce8f8ea', caseKey: 'M41T', kind: 'BURST_ON',
    why: '40 sensitive customer records at once with the flights on: 3 analyses, 17 refused as busy, nothing leaked' },
  { label: 'M41T-flights-off', runId: 'run-1b713adc15c0', caseKey: 'M41T', kind: 'BURST_OFF',
    why: 'the same burst with the flights off: 41 analyses at once' },
  { label: 'M41X-flights-on', runId: 'run-f721ad9b2cac', caseKey: 'M41X', kind: 'BURST_ON',
    why: '30 exports out of the delegation with the flights on: 2 analyses, all refused after the first BLOCK' },
  { label: 'M41X-flights-off', runId: 'run-38b56efb1bcc', caseKey: 'M41X', kind: 'BURST_OFF',
    why: 'the same burst with the flights off: 31 analyses' },
];

async function get(url, optional = false) {
  const response = await fetch(base + url);
  if (!response.ok) {
    if (optional && (response.status === 400 || response.status === 404)) {
      return null;
    }
    throw new Error(`${url} -> HTTP ${response.status}`);
  }
  return response.json();
}

fs.mkdirSync(outDir, { recursive: true });
const cases = new Map();
const index = [];
for (const ref of REFERENCE) {
  if (!cases.has(ref.caseKey)) {
    // The case view is the visitor's agent case (N and T keys); a measurement case (M keys) has none: null.
    cases.set(ref.caseKey, await get(`/api/agent-cases/${ref.caseKey}`, true));
  }
  const run = await get(`/api/runs/${ref.runId}/agent`);
  const snapshot = {
    label: ref.label,
    runId: ref.runId,
    caseKey: ref.caseKey,
    kind: ref.kind,
    why: ref.why,
    capturedAt: new Date().toISOString(),
    case: cases.get(ref.caseKey),
    run,
  };
  fs.writeFileSync(path.join(outDir, `${ref.label}.json`), JSON.stringify(snapshot, null, 1) + '\n', 'utf8');
  index.push({ label: ref.label, runId: ref.runId, caseKey: ref.caseKey, kind: ref.kind, why: ref.why });
  console.log('snapshot', ref.label, ref.runId, `steps=${(run.steps ?? []).length}`);
}
fs.writeFileSync(path.join(outDir, 'index.json'), JSON.stringify(index, null, 1) + '\n', 'utf8');
console.log('index.json', index.length, 'snapshots');
