import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LabCase } from '../../../api/lab';
import { NextLink } from '../../../components/journey/StepParts';
import '../../../i18n';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import { CheckStep } from './CheckStep';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

interface Check {
  readonly answered: boolean;
  readonly reissue_outcome: string | null;
  readonly reissue_elapsed_ms: number | null;
  readonly reissue_delivered: number | null;
}

/** A stored decision record as the screen reads it: the run, its analysis time and its identity check. */
function record(runId: string, check: Check | null) {
  return {
    runId,
    interpretation: { timings: { totalAnalysisMs: 9400 } },
    recovery: check ? { challenge: check } : null,
  };
}

const FINISHED: Check = { answered: true, reissue_outcome: 'DELIVERED', reissue_elapsed_ms: 50, reissue_delivered: 4831 };
const UNFINISHED: Check = { answered: false, reissue_outcome: null, reissue_elapsed_ms: null, reissue_delivered: null };

// The visitor's run, the records by run, and the latest measured run that finished a check, set per test.
const tried = vi.hoisted(() => ({
  runId: 'run-own' as string | null,
  records: {} as Record<string, unknown>,
  resumed: null as unknown,
}));
vi.mock('./tryRun', () => ({
  useTryRun: () => ({
    pending: false,
    view: tried.runId ? { runId: tried.runId, status: 'COMPLETED', challenge: null, steps: [] } : null,
    stored: true,
    runId: tried.runId,
  }),
}));
vi.mock('../../../api/anatomy', () => ({
  useAnatomy: (runId: string | null) => ({
    data: runId ? (tried.records[runId] ?? null) : undefined,
    isPending: false,
  }),
}));
vi.mock('../../../api/measured', () => ({
  useMeasuredCase: () => ({ data: { resumed: tried.resumed }, isPending: false }),
}));

const LAB_CASE = { key: 'A3T', requests: [{}] } as unknown as LabCase;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(null, { status: 404 })),
  );
  Object.assign(tried, { runId: 'run-own', records: {}, resumed: null });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function check() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const see = vi.fn();
  const shown = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/try/owner/after']}>
        <CheckStep
          mode="sync"
          labCase={LAB_CASE}
          see={see}
          flow={{
            back: { to: '/try/owner/reason', label: word('frame.back') },
            next: <NextLink to="/try/follow" label={word('screen.2-5.next')} />,
            teaser: null,
          }}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...shown, see };
}

function steps(): readonly string[] {
  const flow = screen.getByRole('list', { name: word('p2.check.figure') });
  return Array.from(flow.querySelectorAll(':scope > li'), (item) => item.textContent ?? '');
}

/** 2-5 (T7, V-20): one finished identity check in three steps, the visitor's own or another real request named so. */
describe('identity check', () => {
  it("shows the visitor's own finished check with its stored values", () => {
    tried.records['run-own'] = record('run-own', FINISHED);
    const { see } = check();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.2-5.title'));
    expect(screen.getByText(word('screen.2-5.guide'))).toBeInTheDocument();
    const [code, enter, resume] = steps();
    expect(code).toContain(word('p2.check.step.code'));
    expect(code).toContain(fill('p2.check.value.judged', { seconds: '9.4' }));
    expect(enter).toContain(word('p2.check.value.verified'));
    expect(resume).toContain(fill('p2.check.value.resent', { seconds: '0.05', items: '4,831' }));
    expect(screen.getByText(word('frame.source.run'))).toBeInTheDocument();
    expect(see).toHaveBeenCalledWith(5);
  });

  it('says the request had no check and shows a finished one from the current setting as an earlier request', () => {
    tried.records['run-own'] = record('run-own', null);
    tried.records['run-measured'] = record('run-measured', FINISHED);
    tried.resumed = { runId: 'run-measured', startedAt: '2026-10-17T04:33:47Z', current: true };
    check();
    expect(screen.getByText(word('p2.check.guide.notAsked'))).toBeInTheDocument();
    expect(steps()).toHaveLength(3);
    expect(screen.getByText(word('frame.source.earlier'))).toBeInTheDocument();
  });

  it('names a finished check from another setting as such', () => {
    tried.records['run-own'] = record('run-own', null);
    tried.records['run-old'] = record('run-old', FINISHED);
    tried.resumed = { runId: 'run-old', startedAt: '2026-10-17T04:33:47Z', current: false };
    check();
    expect(screen.getByText(word('frame.source.older'))).toBeInTheDocument();
  });

  it('says the own check did not finish before showing another', () => {
    tried.records['run-own'] = record('run-own', UNFINISHED);
    tried.records['run-measured'] = record('run-measured', FINISHED);
    tried.resumed = { runId: 'run-measured', startedAt: '2026-10-17T04:33:47Z', current: true };
    check();
    expect(screen.getByText(word('p2.check.guide.unfinished'))).toBeInTheDocument();
    expect(screen.queryByText(word('p2.check.guide.notAsked'))).not.toBeInTheDocument();
  });

  it('says no finished check exists yet and draws no steps', () => {
    tried.records['run-own'] = record('run-own', null);
    const { see } = check();
    expect(screen.getByText(word('p2.check.guide.noExample'))).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: word('p2.check.figure') })).not.toBeInTheDocument();
    expect(see).not.toHaveBeenCalled();
  });

  it('asks to send first when nothing was sent', () => {
    tried.runId = null;
    check();
    expect(screen.getByText(word('p1.unsent.guide'))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('p1.unsent.go') })).toHaveAttribute('href', '/try/owner/predict');
  });
});
