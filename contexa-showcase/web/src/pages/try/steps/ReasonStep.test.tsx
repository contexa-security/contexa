import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AdverseLabel } from '../../../api/anatomy';
import type { LabCase } from '../../../api/lab';
import type { PromptFact, RunFacts, RunQuality } from '../../../api/promptQuality';
import type { LiveDecision, ReasonCode } from '../../../api/types';
import { NextLink } from '../../../components/journey/StepParts';
import '../../../i18n';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import type { Role } from '../experience';
import { ReasonStep } from './ReasonStep';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

// The try's run, control D's decision and the step's facts and quality as the portal gives them, set per test.
const tried = vi.hoisted(() => ({
  runId: '',
  decision: null as unknown,
  facts: null as unknown,
  quality: null as unknown,
}));
vi.mock('./tryRun', () => ({
  useTryRun: () => ({
    pending: false,
    view: { runId: tried.runId, status: 'COMPLETED' },
    stored: true,
    runId: tried.runId,
  }),
  useTryAnalysis: () => ({ decision: tried.decision, stages: null, wait: null, missing: false }),
}));
vi.mock('../../../api/promptQuality', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../api/promptQuality')>()),
  useRunFacts: (runId: string | null) => ({ data: runId === null ? undefined : tried.facts }),
  useRunQuality: (runId: string | null) => ({ data: runId === null ? undefined : tried.quality }),
}));

const LAB_CASE = { key: 'A3', requests: [{}] } as unknown as LabCase;

/** The model's own sentence of the A3 run of 2026-10-18 (English, kept in the decision details only, F-2). */
const SENTENCE =
  'Policy requires a covering approval, but none exists; this is an unusually timed export to a new target at far ' +
  'above the usual size.';

function line(no: number, factId: string, label: string, value: string): PromptFact {
  return { line: no, factId, label, value, source: 'COMPUTED', grades: ['COMPUTED'] };
}

/**
 * The decision facts of a try's step 1, in the labels and values of the v20 prompt of the A3 run of 2026-10-18
 * (scratchpad prompt_run-8e46), the approval line varied.
 */
function factsOf(runId: string, policySatisfied: string): RunFacts {
  return {
    runId,
    stepNo: 1,
    available: true,
    reason: null,
    bundle: { version: '2026.10.16-v20.23', hash: 'abcdef0123456789', selectionSource: 'REGISTRY', layout: null },
    blocks: [
      {
        block: 'DECISION_FACTS',
        facts: [
          line(38, 'F1', 'DeviationsFromBaseline', '4 of 9 compared -> time 03 seen 0 of 24 (unexplained)'),
          line(40, 'F3', 'Policy', 'EXPORT_APPROVAL requires a covering approval'),
          line(41, 'F4', 'PolicySatisfied', policySatisfied),
          line(42, 'F5', 'Assignment', 'not assigned to GB-500; worked on GB-500 on 0 of the last 30 days'),
          line(44, 'F7', 'OnCall', 'not on call'),
        ],
      },
    ],
  };
}

function qualityOf(reasonCodes: readonly ReasonCode[]): RunQuality {
  return { available: true, reason: null, bundle: null, seal: null, inspection: null, reasonCodes, ribbon: null };
}

function decision(
  finalAction: string,
  reasonCodes: readonly ReasonCode[] = [],
  adverseLabels: readonly AdverseLabel[] = [],
): LiveDecision {
  return {
    finalAction,
    proposedAction: finalAction,
    unresolved: false,
    riskScore: 0.78,
    confidence: 0.96,
    applied: 'BEFORE_RESPONSE',
    reason: {
      canonical: null,
      reasonCodes,
      reasoning: SENTENCE,
      evidenceRefs: ['F1', 'F4'],
      deltas: [],
      baselineDeltaCount: 4,
      resourceSensitivity: null,
    },
    adverseLabels,
    adverseMet: 2,
    adverseChecked: 17,
    totalAnalysisMs: 5922,
    modelCalls: 1,
    promptTokens: 0,
    completionTokens: 0,
  };
}

/** The reason codes of the A3 run of 2026-10-18: five codes on two facts. */
const A3_CODES: readonly ReasonCode[] = [
  { code: 'MIN_P3_POLICY_NOT_SATISFIED', fact: 'F4' },
  { code: 'POLICY_NOT_SATISFIED_NO_RECORD', fact: 'F4' },
  { code: 'DEVIATION_TIME', fact: 'F1' },
  { code: 'DEVIATION_TARGET', fact: 'F1' },
  { code: 'DEVIATION_SIZE', fact: 'F1' },
];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(null, { status: 404 })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function reasons(role: Role) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const next = role === 'owner' ? '2-4' : '1-5';
  const shown = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/try/${role}/reason`]}>
        <ReasonStep
          role={role}
          mode="sync"
          labCase={LAB_CASE}
          see={vi.fn()}
          flow={{
            back: { to: `/try/${role}/result`, label: word('frame.back') },
            next: <NextLink to={`/try/${role}/after`} label={word(`screen.${next}.next`)} />,
            teaser: null,
          }}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return shown;
}

function figure() {
  return screen.getByRole('group', { name: word('p1.reason.figure') });
}

function cards(): readonly HTMLElement[] {
  return Array.from(figure().querySelectorAll<HTMLElement>('li'));
}

/** 1-5: each cited fact once in plain words, then the judgment; no engine code, fact ID or model sentence. */
describe('try 1 reasons', () => {
  it('draws each cited fact once with the plain words of its reasons and ends at the judgment', () => {
    Object.assign(tried, {
      runId: 'run-8e46bceb68a9',
      decision: decision('ESCALATE', A3_CODES),
      facts: factsOf('run-8e46bceb68a9', 'no — no approval for GB-500'),
      quality: qualityOf(A3_CODES),
    });
    reasons('attacker');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.1-5.title'));
    expect(screen.getByText(word('screen.1-5.guide'))).toBeInTheDocument();
    // Five codes on two facts: two cards, each fact once, in the server's order.
    expect(cards().map((card) => card.dataset.fact)).toEqual(['F4', 'F1']);
    const [policy, deviations] = cards();
    expect(policy).toHaveTextContent(word('fact.label.PolicySatisfied'));
    expect(policy).toHaveTextContent(word('reasonCode.MIN_P3_POLICY_NOT_SATISFIED'));
    expect(policy).toHaveTextContent(word('reasonCode.POLICY_NOT_SATISFIED_NO_RECORD'));
    expect(deviations).toHaveTextContent(word('fact.label.DeviationsFromBaseline'));
    for (const code of ['DEVIATION_TIME', 'DEVIATION_TARGET', 'DEVIATION_SIZE']) {
      expect(deviations).toHaveTextContent(word(`reasonCode.${code}`));
    }
    // The figure ends at the judgment: held for review.
    expect(within(figure()).getByText(word('verdict.review'))).toBeInTheDocument();
    // One details chip, and the way on is the copy source's question.
    expect(screen.getAllByRole('button', { name: word('frame.detail') })).toHaveLength(1);
    expect(screen.getByRole('link', { name: word('screen.1-5.next') })).toHaveAttribute('href', '/try/attacker/after');
  });

  it('shows no engine code, fact ID, source chip, original, model sentence or prompt link', () => {
    Object.assign(tried, {
      runId: 'run-8e46bceb68a9',
      decision: decision('ESCALATE', A3_CODES),
      facts: factsOf('run-8e46bceb68a9', 'no — no approval for GB-500'),
      quality: qualityOf(A3_CODES),
    });
    const { container } = reasons('attacker');
    const text = container.textContent ?? '';
    expect(text).not.toMatch(/\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b/);
    expect(text).not.toMatch(/\bF\d{1,2}\b/);
    expect(text).not.toMatch(/run-[0-9a-f]{6,}/);
    expect(text).not.toContain(SENTENCE);
    expect(text).not.toContain(word('fact.source.COMPUTED'));
    for (const gone of [
      'e1.reason.wrote',
      'e1.reason.free',
      'e1.reason.details',
      'e1.reason.promptLink',
      'source.original',
      'reasonChain.check',
    ]) {
      expect(text).not.toContain(word(gone).replace(/\{\{\w+\}\}.*$/, ''));
    }
    expect(container.querySelector('[data-original]')).toBeNull();
    expect(container.querySelector('details, blockquote, code')).toBeNull();
  });

  it('shows three facts at most and says the others are in the details', () => {
    const codes: readonly ReasonCode[] = [
      { code: 'MIN_P3_POLICY_NOT_SATISFIED', fact: 'F4' },
      { code: 'DEVIATION_TIME', fact: 'F1' },
      { code: 'POLICY_NOT_SATISFIED_NO_RECORD', fact: 'F5' },
      { code: 'ON_CALL', fact: 'F7' },
    ];
    Object.assign(tried, {
      runId: 'run-four',
      decision: decision('ESCALATE', codes),
      facts: factsOf('run-four', 'no — no approval for GB-500'),
      quality: qualityOf(codes),
    });
    reasons('attacker');
    expect(cards().map((card) => card.dataset.fact)).toEqual(['F4', 'F1', 'F5']);
    expect(screen.getByText(word('p1.reason.more'))).toBeInTheDocument();
  });

  it("uses the decision's own reason codes while the sealed ones cannot be read", () => {
    Object.assign(tried, {
      runId: 'run-8e46bceb68a9',
      decision: decision('ESCALATE', A3_CODES),
      facts: factsOf('run-8e46bceb68a9', 'no — no approval for GB-500'),
      quality: { ...qualityOf([]), available: false },
    });
    reasons('attacker');
    expect(cards().map((card) => card.dataset.fact)).toEqual(['F4', 'F1']);
  });

  it("draws the decision's recorded facts when it recorded no reason codes", () => {
    Object.assign(tried, {
      runId: 'run-old',
      decision: decision('ESCALATE'),
      facts: null,
      quality: qualityOf([]),
    });
    reasons('attacker');
    expect(cards()[0]).toHaveTextContent(fill('e1.reason.differs', { n: 4 }));
    expect(within(figure()).getByText(word('verdict.review'))).toBeInTheDocument();
  });

  it('asks why it was let through when Contexa let try 1 pass', () => {
    const codes: readonly ReasonCode[] = [{ code: 'BASELINE_MATCH', fact: 'F1' }];
    Object.assign(tried, {
      runId: 'run-pass',
      decision: decision('ALLOW', codes),
      facts: factsOf('run-pass', 'no — no approval for GB-500'),
      quality: qualityOf(codes),
    });
    reasons('attacker');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('p1.reason.title.pass'));
    expect(screen.getByText(word('p1.reason.guide.pass'))).toBeInTheDocument();
  });

  it('asks to send first when nothing was sent', () => {
    Object.assign(tried, { runId: '', decision: null, facts: null, quality: null });
    reasons('attacker');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.1-5.title'));
    expect(screen.getByText(word('p1.unsent.guide'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('p1.unsent.go') })).toHaveAttribute('href', '/try/attacker/predict');
    expect(screen.queryByRole('group', { name: word('p1.reason.figure') })).not.toBeInTheDocument();
  });
});

/** 2-4: try 1's figure again, the company approval marked as the one thing that changed, ending at a pass. */
describe('try 2 reasons', () => {
  it('marks the approval fact as what changed and keeps the differences card of try 1', () => {
    Object.assign(tried, {
      runId: 'run-try1',
      decision: decision('ESCALATE', A3_CODES),
      facts: factsOf('run-try1', 'no — no approval for GB-500'),
      quality: qualityOf(A3_CODES),
    });
    const first = reasons('attacker');
    const firstDeviations = required(cards()[1], 'F1').textContent;
    first.unmount();

    const approval = 'yes — approval APR-7731 for GB-500 up to 5,000 items, issued before the request';
    const codes: readonly ReasonCode[] = [
      { code: 'APPROVAL_COVERS', fact: 'F4' },
      { code: 'DEVIATION_TIME', fact: 'F1' },
      { code: 'DEVIATION_TARGET', fact: 'F1' },
      { code: 'DEVIATION_SIZE', fact: 'F1' },
    ];
    Object.assign(tried, {
      runId: 'run-try2',
      decision: decision('ALLOW', codes),
      facts: factsOf('run-try2', approval),
      quality: qualityOf(codes),
    });
    const { container } = reasons('owner');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.2-4.title'));
    expect(screen.getByText(word('screen.2-4.guide'))).toBeInTheDocument();
    const [changed, deviations] = cards();
    expect(changed).toHaveAttribute('data-changed');
    expect(changed).toHaveAttribute('data-fact', 'F4');
    expect(changed).toHaveTextContent(word('p2.reason.changed'));
    expect(changed).toHaveTextContent(word('reasonCode.APPROVAL_COVERS'));
    // The differences read as in try 1; the figure ends at a pass.
    expect(deviations?.textContent).toBe(firstDeviations);
    expect(within(figure()).getByText(word('verdict.allow'))).toBeInTheDocument();
    // The approval's own line stays in the decision details.
    expect(container.textContent).not.toContain('APR-7731');
  });

  it('shows the changed approval first even when no reason cites it', () => {
    const codes: readonly ReasonCode[] = [{ code: 'DEVIATION_TIME', fact: 'F1' }];
    Object.assign(tried, {
      runId: 'run-try2',
      decision: decision('ALLOW', codes, [
        { label: 'policysatisfied', condition: 'PolicySatisfied: no', values: ['yes'], met: false },
      ]),
      facts: factsOf('run-try2', 'yes — approval APR-7731 for GB-500'),
      quality: qualityOf(codes),
    });
    reasons('owner');
    const [changed, deviations] = cards();
    expect(changed).toHaveAttribute('data-fact', 'F4');
    expect(changed).toHaveTextContent(word('p2.reason.changed'));
    expect(changed).toHaveTextContent(word('e1.reason.policyMet'));
    expect(deviations).toHaveAttribute('data-fact', 'F1');
  });
});
