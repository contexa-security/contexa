import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LabCase } from '../../../api/lab';
import type { RunFacts, RunQuality } from '../../../api/promptQuality';
import type { LiveDecision, ReasonCode } from '../../../api/types';
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

// The try's run, control D's decision and the step's facts and quality as the portal gives them, set per
// test.
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

/**
 * The decision facts of a try's step 1 (this test's own values): the same differences, the approval fact
 * varied.
 */
function factsOf(runId: string, policySatisfied: string): RunFacts {
  return {
    runId,
    stepNo: 1,
    available: true,
    reason: null,
    bundle: {
      version: '2026.10.16-v20.23',
      hash: 'abcdef0123456789',
      selectionSource: 'REGISTRY',
      layout: null,
    },
    blocks: [
      {
        block: 'DECISION_FACTS',
        facts: [
          {
            line: 37,
            factId: 'F1',
            label: 'DeviationsFromBaseline',
            value: '3 of 10 compared -> time 03 seen 0 of 25 (unexplained)',
            source: 'COMPUTED',
            grades: ['COMPUTED'],
          },
          {
            line: 38,
            factId: 'F2',
            label: 'Policy',
            value: 'exports of GB-500 need an approval',
            source: 'HOST',
            grades: ['HOST'],
          },
          {
            line: 39,
            factId: 'F3',
            label: 'PolicySatisfied',
            value: policySatisfied,
            source: 'COMPUTED',
            grades: ['COMPUTED'],
          },
        ],
      },
    ],
  };
}

function qualityOf(reasonCodes: readonly ReasonCode[]): RunQuality {
  return {
    available: true,
    reason: null,
    bundle: null,
    seal: null,
    inspection: null,
    reasonCodes,
    ribbon: null,
  };
}

function decision(finalAction: string): LiveDecision {
  return {
    finalAction,
    proposedAction: finalAction,
    unresolved: false,
    riskScore: null,
    confidence: null,
    applied: 'BEFORE_RESPONSE',
    reason: {
      canonical: null,
      reasoning: null,
      evidenceRefs: [],
      deltas: [],
      baselineDeltaCount: 3,
      resourceSensitivity: null,
    },
    adverseLabels: [],
    adverseMet: 0,
    adverseChecked: 17,
    totalAnalysisMs: null,
    modelCalls: 1,
    promptTokens: 0,
    completionTokens: 0,
  };
}

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
  const shown = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/try/${role}/reason`]}>
        <ReasonStep
          role={role}
          mode="sync"
          labCase={LAB_CASE}
          see={vi.fn()}
          flow={{ back: null, next: null, teaser: null }}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const chain = screen.getByRole('group', { name: word('reasonChain.title') });
  const cards: Record<string, string> = {};
  for (const card of chain.querySelectorAll<HTMLElement>('[data-fact]')) {
    cards[card.dataset.fact ?? ''] = card.textContent ?? '';
  }
  return { shown, chain, cards, rows: chain.querySelectorAll('ol > li').length };
}

/** U3-4: try 2's reasons in the same shape as try 1's, one fact changed and the line ending at allow. */
describe('try 2 reasons', () => {
  it("draws try 1's chain again: only the approval fact reads differently and it ends at allow", async () => {
    Object.assign(tried, {
      runId: 'run-try1',
      decision: decision('CHALLENGE'),
      facts: factsOf('run-try1', 'no — no approval for GB-500'),
      quality: qualityOf([
        { code: 'MIN_P3_POLICY_NOT_SATISFIED', fact: 'F3' },
        { code: 'DEVIATION_TIME', fact: 'F1' },
      ]),
    });
    const first = reasons('attacker');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('e1.reason.title.CHALLENGE'));
    expect(within(first.chain).getByText(word('verdict.verify'))).toBeInTheDocument();
    first.shown.unmount();

    const approval = 'yes — approval APR-7731 for GB-500 up to 5,000 items, issued before the request';
    Object.assign(tried, {
      runId: 'run-try2',
      decision: decision('ALLOW'),
      facts: factsOf('run-try2', approval),
      quality: qualityOf([
        { code: 'APPROVAL_COVERS', fact: 'F3' },
        { code: 'DEVIATION_TIME', fact: 'F1' },
      ]),
    });
    const second = reasons('owner');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('e2.reason.title.ALLOW'));
    expect(within(second.chain).getByText(word('verdict.allow'))).toBeInTheDocument();
    // The same shape: the same rows on the same facts, and of their cards only the approval fact's differs.
    expect(second.rows).toBe(first.rows);
    expect(Object.keys(second.cards)).toEqual(Object.keys(first.cards));
    expect(second.cards.F1).toBe(first.cards.F1);
    expect(second.cards.F3).not.toBe(first.cards.F3);
    expect(first.cards.F3).toContain(word('prompt.plain.approvalMissing'));
    expect(second.cards.F3).not.toContain(word('prompt.plain.approvalMissing'));
    // Its original line is the server's: the valid approval, issued before the request.
    const card = required(second.chain.querySelector<HTMLElement>('[data-fact="F3"]'), 'F3');
    await userEvent.click(within(card).getByRole('button', { name: word('source.original') }));
    expect(within(card).getByText(`PolicySatisfied: ${approval}`)).toHaveAttribute('data-original');
  });
});
