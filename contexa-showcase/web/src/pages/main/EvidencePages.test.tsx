import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import CheckPage from './CheckPage';
import EvidenceMapPage from './EvidenceMapPage';
import EvidencePromptPage from './EvidencePromptPage';
import EvidenceVerdictPage from './EvidenceVerdictPage';

/*
 * Review before the guide videos (2026-10-21, 10절 L-02, L-32, L-33, L-34, L-36): the screens of group 3 and 4-4 as the
 * visitor's own stored runs draw them. The values are those of the review's runs (S13 run-e7177ebe6785, S14
 * run-b9b8c11c8759), cut to what the screens read.
 */
const RUN = 'run-e7177ebe6785';
const CHECK_RUN = 'run-b9b8c11c8759';

function fact(line: number, factId: string | null, label: string, value: string, source = 'HOST') {
  return { line, factId, label, value, source, grades: [source] };
}

const FACTS = {
  runId: RUN,
  stepNo: 1,
  available: true,
  reason: null,
  bundle: {
    version: '2026.10.20-v21.8',
    hash: '9a9984bad390',
    selectionSource: 'CONFIGURATION',
    layout: 'v21',
  },
  blocks: [
    {
      block: 'REQUEST',
      facts: [
        fact(30, 'R2', 'Time', 'Wed 14:20', 'COMPUTED'),
        fact(34, 'R6', 'Size', '480 items'),
        fact(35, 'R7', 'ResourceClass', 'SENSITIVE (sensitivity HIGH)'),
        fact(36, 'R8', 'Network', '10.40.21.174 (10.40.21.0/24, zone CORPORATE)', 'COMPUTED'),
      ],
    },
    { block: 'SESSION', facts: [fact(21, 'S1', 'LoginMethod', 'PASSWORD+ONE_TIME_CODE (assurance AAL2)')] },
    {
      block: 'USER_BASELINE',
      facts: [
        fact(3, 'B1', 'BaselineStatus', 'ESTABLISHED (49 learned requests)', 'LEARNED'),
        fact(4, null, 'UsualHours', '11-12, 15-16', 'LEARNED'),
        fact(7, null, 'UsualDevices', 'Edge/140 on WINDOWS', 'LEARNED'),
        fact(12, null, 'UsualExportSize', 'up to 15 items per export', 'LEARNED'),
      ],
    },
    {
      block: 'DECISION_FACTS',
      facts: [
        fact(40, 'F1', 'DeviationsFromBaseline', '2 of 9 compared -> device Safari/18 on MAC', 'COMPUTED'),
        fact(42, 'F3', 'Policy', 'EXPORT_APPROVAL requires a covering approval; none found'),
        fact(
          43,
          'F4',
          'Assignment',
          'assigned to HX-310 (DESIGN); worked on HX-310 on 21 of the last 30 days',
        ),
        fact(44, 'F5', 'Ticket', 'no ticket found'),
      ],
    },
  ],
};

const ANATOMY = {
  runId: RUN,
  stepNo: 1,
  recovery: null,
  interpretation: {
    calls: [
      { callNo: 1, model: 'gpt-6-luna', elapsedMs: 9000, answer: '{"action":"ESCALATE"}' },
      { callNo: 2, model: 'gpt-6-luna', elapsedMs: 7400, answer: '{"action":"CHALLENGE"}' },
    ],
    recorded: {
      proposedAction: 'CHALLENGE',
      finalAction: 'CHALLENGE',
      riskScore: 0.32,
      confidence: 0.82,
      reasoning: null,
      reasoningCode: null,
      mitre: null,
      unresolved: false,
      failureType: null,
      fallbackCategory: null,
      applied: 'BEFORE_RESPONSE',
      evidenceRefs: [],
    },
    timings: {
      promptBuildMs: 80,
      ragVectorMs: null,
      llmLatencyMs: 16400,
      totalAnalysisMs: 16440,
      events: [],
    },
    timeline: [],
    sinceStartMs: [],
    promptTokens: 12780,
    completionTokens: 1025,
  },
  learning: {
    template: { baselineUpdateCount: 49 },
    atRunEnd: { baselineUpdateCount: 49 },
    newBehaviourDocuments: [],
  },
  juxtaposition: {
    departures: [],
    companyFacts: [],
    sensitivity: 'HIGH',
    modelReasoning: null,
    recordedReasoning: null,
    coreAdverseLabels: [],
    adverseMet: 0,
    adverseChecked: 0,
  },
  promptLines: { layout: 'V20_BLOCKS', total: 153, system: 91, user: 62, sections: [], bundles: [] },
  figures: {
    workProfileWindow: '7d',
    workProfileObservations: 21,
    baselineBefore: 49,
    baselineAfter: 49,
    baselineAdded: 0,
    documentsBefore: null,
    documentsAfter: null,
    documentsForThisRequest: 0,
    departureCount: 2,
  },
};

const QUALITY = {
  available: true,
  reason: null,
  bundle: FACTS.bundle,
  seal: {
    packageHash: '31b477aa00112233445566778899aabbccddeeff00112233445566778813d4',
    capturedAt: '2026-10-20T23:31:18Z',
  },
  inspection: {
    checks: [
      { code: 'SEAL_INTEGRITY', matched: 12, mismatched: 0, unverifiable: 0 },
      { code: 'FACT_ACCURACY', matched: 35, mismatched: 0, unverifiable: 1 },
      { code: 'DECISION_FACT_MATCH', matched: 17, mismatched: 0, unverifiable: 2 },
    ],
  },
  reasonCodes: [{ code: 'ASSIGNED_TARGET', fact: 'F4' }],
  hypotheses: [{ id: 'H1', name: null, assessment: 'MOST_LIKELY', for: ['F4'], against: ['F1'] }],
  ribbon: { factAccuracy: { matched: 35, total: 35 } },
};

const RECEIVED = {
  runId: RUN,
  companyTime: '2026-09-30T14:20:00Z',
  usualVsNow: [],
  usual: {
    accessHour: { label: 'UsualHours', values: ['11', '12', '15', '16'] },
    device: { label: 'UsualDevices', values: ['Edge/140 · Windows'] },
    size: { label: 'UsualExportSize', values: ['15'] },
  },
  departureCount: 2,
  businessFacts: [
    { code: 'NO_APPROVAL', value: null },
    { code: 'ACCESS_DAYS_LAST_30', value: '21' },
  ],
  sensitivity: 'HIGH',
};

function layer(control: string, outcome: string, httpStatus: number, deliveredItems: number) {
  return {
    control,
    outcome,
    verdict: null,
    httpStatus,
    ruleId: null,
    reason: null,
    ruleFacts: {},
    evidence: { deliveredItems, responseMs: 30 },
  };
}

/** One request of the real user's run on 4-4, as stored: the four existing approaches and Contexa. */
function stepResult(c1: [string, number, number], d: [string, number, number]) {
  return {
    companyTime: '2026-09-30T03:17:00Z',
    layers: [
      layer('A', 'DELIVERED', 200, d[2] || c1[2] || 1),
      layer('B', 'DELIVERED', 200, d[2] || c1[2] || 1),
      layer('C1', c1[0], c1[1], c1[2]),
      layer('C2', 'DELIVERED', 200, d[2] || c1[2] || 1),
      layer('D', d[0], d[1], d[2]),
    ],
    engineReason: null,
    companyFacts: [],
    tally: {},
    existingTally: {},
  };
}

const S14 = {
  key: 'S14',
  version: 1,
  title: {
    ko: '출장지에서 새 노트북으로 하는 새벽 정상 업무',
    en: 'Normal work at dawn from a business trip',
  },
  classification: 'NORMAL',
  steps: 3,
  conditions: { employee: 'eng-k', timeSlot: 'DAWN', place: 'TRAVEL', device: 'NEW' },
  facts: [{ kind: 'TRAVEL', city: 'Singapore', network: '198.51.100.0/24' }],
  requests: [
    {
      operation: 'DOCUMENT_READ',
      project: null,
      document: { project: 'HX-310', type: 'DRAWING', position: 5, fact: null },
    },
    {
      operation: 'DOCUMENT_READ',
      project: null,
      document: { project: 'HX-310', type: 'DRAWING', position: 6, fact: null },
    },
    { operation: 'EXPORT', project: 'HX-310', document: null, items: 12 },
  ],
};

const BODIES: Readonly<Record<string, unknown>> = {
  '/api/visitor': { predictions: {} },
  '/api/journey': {
    state: { route: 'DEFAULT', act: 4, step: 'check', differences: [] },
    runs: [
      {
        runId: RUN,
        scenarioKey: 'S13',
        classification: 'THREAT',
        status: 'COMPLETED',
        lab: false,
        business: { A: 'MISSED', B: 'MISSED', C1: 'MISSED', C2: 'MISSED', D: 'STOPPED' },
        engineAction: 'CHALLENGE',
        exposedItems: 0,
        correct: true,
        requestedItems: 480,
        steps: 1,
      },
      {
        runId: CHECK_RUN,
        scenarioKey: 'S14',
        classification: 'NORMAL',
        status: 'COMPLETED',
        lab: false,
        business: { A: 'PASSED', B: 'PASSED', C1: 'HALTED', C2: 'PASSED', D: 'PASSED_AFTER_CHECK' },
        engineAction: 'CHALLENGE',
        exposedItems: 14,
        correct: true,
        requestedItems: null,
        steps: 3,
      },
    ],
    predictions: [],
  },
  '/api/lab/options': {
    employees: [{ key: 'eng-k', displayName: 'Engineer K' }],
    timeSlots: [],
    items: [],
    operations: [],
    cases: [S14],
    calls: [],
    assessmentReasons: [],
  },
  [`/api/runs/${RUN}/steps/1/anatomy`]: ANATOMY,
  [`/api/runs/${RUN}/steps/1/facts`]: FACTS,
  [`/api/runs/${RUN}/steps/1/quality`]: QUALITY,
  [`/api/runs/${RUN}/steps/1/received`]: RECEIVED,
  [`/api/runs/${RUN}/steps/1/result`]: stepResult(['DELIVERED', 200, 480], ['REFUSED', 401, 0]),
  [`/api/runs/${CHECK_RUN}/steps/1/result`]: stepResult(['DELIVERED', 200, 1], ['DELIVERED', 200, 1]),
  [`/api/runs/${CHECK_RUN}/steps/2/result`]: stepResult(['DELIVERED', 200, 1], ['REFUSED', 401, 0]),
  [`/api/runs/${CHECK_RUN}/steps/3/result`]: stepResult(['REFUSED', 403, 0], ['DELIVERED', 200, 12]),
  [`/api/runs/${CHECK_RUN}/steps/2/anatomy`]: {
    ...ANATOMY,
    runId: CHECK_RUN,
    stepNo: 2,
    recovery: {
      challenge: {
        answered: true,
        reason: null,
        challenged_at: '2026-10-20T23:32:27.780642Z',
        code_requested_at: '2026-10-20T23:32:28.135794Z',
        verified_at: '2026-10-20T23:32:30.246258Z',
        reissue_sent_at: '2026-10-20T23:32:30.246258Z',
        reissue_outcome: 'DELIVERED',
        reissue_status: 200,
        reissue_delivered: 1,
        reissue_elapsed_ms: 54,
      },
      release: null,
    },
  },
};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = BODIES[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(page: ReactElement, path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={page} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Korean words of a recorded time's zone, never inside a code (L-02). */
function zoneOutsideCode() {
  const zones = screen.getAllByText(new RegExp(i18n.t('main.utc').replace(/[()]/g, '\\$&')));
  for (const zone of zones) {
    expect(zone.closest('code')).toBeNull();
  }
}

describe('3-1, the seven stages (L-32, L-02)', () => {
  it('draws every stage alike, each with the name of its raw line', async () => {
    open(<EvidenceMapPage />, '/evidence/map');
    await screen.findByText('2026.10.20-v21.8');
    expect(document.querySelector('[data-focus]')).toBeNull();
    const stages = screen
      .getAllByRole('button', { name: i18n.t('main.3-1.open') })
      .map((button) => button.closest('li'));
    expect(stages).toHaveLength(7);
    for (const stage of stages) {
      expect(stage?.querySelector('[data-raw]'), stage?.textContent ?? '').not.toBeNull();
    }
    // The LLM stage names what the model proposed; the company records stage the policy line of a v21 prompt.
    expect(screen.getByText('proposedAction: CHALLENGE')).toBeInTheDocument();
    expect(screen.getByText('F3 Policy')).toBeInTheDocument();
  });

  // 구현계획 AC-N2: the seven stages are the view; each stage's value and raw line, and the seal, the learning chart and
  // the source wait under a line.
  it("keeps each stage's value under a line of its own and the seal and the chart under one more", async () => {
    const { container } = open(<EvidenceMapPage />, '/evidence/map');
    await screen.findByText('2026.10.20-v21.8');
    const values = Array.from(container.querySelectorAll('details[data-fold="stage-values"]'));
    expect(values).toHaveLength(7);
    expect(values.every((fold) => !(fold as HTMLDetailsElement).open)).toBe(true);
    for (const fold of values) {
      expect(fold.closest('li')?.querySelector('[data-raw]')).not.toBeNull();
      expect(fold.contains(fold.closest('li')?.querySelector('[data-raw]') ?? null)).toBe(true);
    }
    // what each stage is sits with its value, so a stage in view is its name, the line that opens its value and its record
    for (const fold of values) {
      expect(fold.querySelector('[class*="stageSub"]')).not.toBeNull();
    }
    const seal = container.querySelector('details[data-fold="stage-seal"]') as HTMLDetailsElement | null;
    expect(seal).not.toBeNull();
    expect(seal?.open).toBe(false);
    expect(seal?.textContent).toContain(i18n.t('main.3-1.sealWord'));
  });

  it('sets the words of a raw line apart from its code', async () => {
    open(<EvidenceMapPage />, '/evidence/map');
    expect((await screen.findByText('2026.10.20-v21.8')).closest('code')).not.toBeNull();
    expect(screen.getByText(i18n.t('main.3-1.prompt.bundle')).closest('code')).toBeNull();
    zoneOutsideCode();
  });
});

describe('3-2, the inputs and the prompt lines (L-33, L-04)', () => {
  it('lists the prompt lines in the order of the prompt and names on each card the lines it became', async () => {
    open(<EvidencePromptPage />, '/evidence/prompt');
    await screen.findByText(i18n.t('main.3-2.legend'));
    const lines = Array.from(document.querySelectorAll('[data-line]')).map((line) =>
      Number(line.getAttribute('data-line')),
    );
    expect(lines).toEqual([...lines].sort((a, b) => a - b));
    expect(lines).toContain(42);
    expect(
      screen.getByText(i18n.t('main.3-2.lines', { lines: '003 · 004 · 007 · 012', count: 4 })),
    ).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.3-2.lines', { lines: '035', count: 1 }))).toBeInTheDocument();
    // the lines each input became sit with the prompt, under the fold that opens it
    expect(
      screen
        .getByText(i18n.t('main.3-2.lines', { lines: '035', count: 1 }))
        .closest('details[data-fold="prompt-lines"]'),
    ).not.toBeNull();
  });
});

describe('3-2 keeps the four inputs in view (구현계획 AC-N2)', () => {
  it('shows the four inputs in plain words and keeps the prompt lines under one line', async () => {
    const { container } = open(<EvidencePromptPage />, '/evidence/prompt');
    await screen.findByText(i18n.t('main.3-2.legend'));
    const fold = container.querySelector('details[data-fold="prompt-lines"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    const lines = Array.from(container.querySelectorAll('[data-line]'));
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.every((line) => fold?.contains(line))).toBe(true);
    // the four inputs are outside the fold
    for (const group of ['learned', 'request', 'company', 'sensitivity']) {
      const card = container.querySelector(`li[data-group="${group}"]:not([data-line])`);
      expect(card, group).not.toBeNull();
      expect(fold?.contains(card)).toBe(false);
    }
  });
});

describe('3-2 says each input in one short line (구현계획 AC-N2)', () => {
  it('keeps the usual hours, devices and largest export of the learned pattern with the prompt lines, not in the card', async () => {
    const { container } = open(<EvidencePromptPage />, '/evidence/prompt');
    await screen.findByText(i18n.t('main.3-2.legend'));
    const card = container.querySelector('li[data-group="learned"]:not([data-line])') as HTMLElement;
    expect(card.textContent).not.toContain('평소 시각');
    const fold = container.querySelector('details[data-fold="prompt-lines"]') as HTMLDetailsElement;
    expect(fold.textContent).toContain('평소 시각');
    expect(fold.textContent).toContain('평소 기기');
  });
});

describe('3-2 keeps the button of the whole prompt with the prompt (구현계획 AC-N2)', () => {
  it('has the whole-prompt button under the fold, not in the foot', async () => {
    const { container } = open(<EvidencePromptPage />, '/evidence/prompt');
    await screen.findByText(i18n.t('main.3-2.legend'));
    const fold = container.querySelector('details[data-fold="prompt-lines"]') as HTMLDetailsElement;
    expect(within(fold).getByRole('button', { name: i18n.t('main.3-2.whole') })).toBeInTheDocument();
    expect(container.querySelector('[data-zone="actions"]')?.textContent).not.toContain(i18n.t('main.3-2.whole'));
  });
});

describe('3-3, the answer and the checks (L-34, L-02)', () => {
  it('greens only what matched and keeps the zone of the seal time out of the code', async () => {
    open(<EvidenceVerdictPage />, '/evidence/verdict');
    expect(await screen.findByText('확인 불가 2')).toHaveAttribute('data-tone', 'unknown');
    expect(screen.getByText('17건 일치')).toHaveAttribute('data-tone', 'ok');
    expect(screen.getByText('gpt-6-luna')).toHaveAttribute('data-code');
    zoneOutsideCode();
  });
});

describe('4-4, the real user checked on the way (L-36)', () => {
  it('names the second drawing apart and keeps the extra check of the finished run', async () => {
    open(<CheckPage />, '/normal/check');
    expect(await screen.findByText(i18n.t('main.4-4.record', { n: 2 }))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.4-4.read', { project: 'HX-310' }))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('main.4-4.readAnother', { project: 'HX-310' }))).toBeInTheDocument();
  });
});
