import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EngineActions } from '../../../api/engine';
import type { LabCase, LabEmployee } from '../../../api/lab';
import type { LiveDecision } from '../../../api/types';
import { NextLink } from '../../../components/journey/StepParts';
import '../../../i18n';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import { AfterStep } from './AfterStep';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

// The try's run, control D's decision of it, its recorded check and the engine's hold times, set per test.
const tried = vi.hoisted(() => ({
  runId: 'run-8e46bceb68a9',
  decision: null as unknown,
  stage: null as string | null,
  actions: null as unknown,
}));
vi.mock('./tryRun', () => ({
  useTryRun: () => ({
    pending: false,
    view: { runId: tried.runId, status: 'COMPLETED', challenge: null, steps: [] },
    stored: true,
    runId: tried.runId,
  }),
  useTryAnalysis: () => ({ decision: tried.decision, stages: null, wait: null, missing: tried.decision === null }),
  useStoredCheck: () => tried.stage,
}));
vi.mock('../../../api/engine', () => ({
  useEngineActions: () => ({ data: tried.actions, isLoading: false }),
}));

const LAB_CASE = { key: 'A3', requests: [{}] } as unknown as LabCase;
const EMPLOYEE = { key: 'adm-a', displayName: 'Administrator A' } as unknown as LabEmployee;

/** Hold times as the engine publishes them (this test's own values, not the core's defaults). */
function actionsOf(escalate: number | null, block: number | null): EngineActions {
  return {
    ALLOW: { httpStatus: 200, ttlSeconds: null },
    CHALLENGE: { httpStatus: 401, ttlSeconds: 1800 },
    ESCALATE: { httpStatus: 423, ttlSeconds: escalate },
    BLOCK: { httpStatus: 403, ttlSeconds: block },
  };
}

function decision(finalAction: string, applied: LiveDecision['applied'] = 'BEFORE_RESPONSE'): LiveDecision {
  return {
    finalAction,
    proposedAction: finalAction,
    unresolved: false,
    riskScore: 0.78,
    confidence: 0.96,
    applied,
    reason: null,
    adverseLabels: [],
    adverseMet: 0,
    adverseChecked: 17,
    totalAnalysisMs: 5922,
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
  Object.assign(tried, { runId: 'run-8e46bceb68a9', decision: null, stage: null, actions: actionsOf(300, null) });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function after() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const see = vi.fn();
  const shown = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/try/attacker/after']}>
        <AfterStep
          role="attacker"
          mode="sync"
          labCase={LAB_CASE}
          employee={EMPLOYEE}
          see={see}
          flow={{
            back: { to: '/try/attacker/reason', label: word('frame.back') },
            next: <NextLink to="/try/attacker/end" label={word('screen.1-6.next')} />,
            teaser: null,
          }}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...shown, see };
}

function steps(): readonly string[] {
  const flow = screen.getByRole('list', { name: word('p1.after.figure') });
  return Array.from(flow.querySelectorAll(':scope > li'), (item) => item.textContent ?? '');
}

/** 1-6 (F-7): one flow per judgment of the visitor's run, never an empty follow-up. */
describe('after the stop', () => {
  it('holds the request for the security admin and blocks it past the hold time the engine publishes', () => {
    tried.decision = decision('ESCALATE');
    const { see } = after();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.1-6.title'));
    expect(screen.getByText(word('screen.1-6.guide.review'))).toBeInTheDocument();
    expect(steps()).toEqual([
      word('p1.after.review.held'),
      word('p1.after.review.admin'),
      fill('p1.after.review.expire', { time: fill('p1.after.minutes', { n: 5 }) }),
    ]);
    // One source line naming both sources, with the record behind it.
    expect(screen.getByText(word('p1.after.source.timed'))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: word('frame.source.open') })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: word('screen.1-6.next') })).toHaveAttribute('href', '/try/attacker/end');
    expect(see).toHaveBeenCalledWith(5);
  });

  it("takes the hold time from the engine's answer, not from the screen", () => {
    tried.decision = decision('ESCALATE');
    tried.actions = actionsOf(90, null);
    after();
    expect(steps()[2]).toBe(fill('p1.after.review.expire', { time: fill('p1.after.seconds', { n: 90 }) }));
  });

  it('holds the next requests when the judgment applies from the next request on', () => {
    tried.decision = decision('ESCALATE', 'NEXT_REQUEST');
    after();
    expect(steps()[0]).toBe(word('p1.after.review.heldNext'));
  });

  it("sends the code to the real employee's mailbox, which the account holder never gets", () => {
    tried.decision = decision('CHALLENGE');
    tried.stage = 'NO_MAILBOX';
    after();
    expect(screen.getByText(word('screen.1-6.guide.verify'))).toBeInTheDocument();
    expect(steps()).toEqual([
      word('p1.after.verify.asked'),
      fill('p1.after.verify.mailbox', { name: 'Administrator A' }),
      word('p1.after.verify.holder'),
    ]);
    expect(screen.getByText(word('p1.after.source'))).toBeInTheDocument();
  });

  it('keeps a block until an admin lifts it', () => {
    tried.decision = decision('BLOCK');
    after();
    expect(screen.getByText(word('p1.after.guide.block'))).toBeInTheDocument();
    expect(steps()).toEqual([word('p1.after.block.stopped'), word('p1.after.block.untilLifted')]);
  });

  it('says nothing followed when the request was not stopped, without a figure or a source line', () => {
    tried.decision = decision('ALLOW');
    const { see } = after();
    expect(screen.getByText(word('p1.after.guide.none'))).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: word('p1.after.figure') })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: word('frame.source.open') })).not.toBeInTheDocument();
    expect(see).not.toHaveBeenCalled();
  });

  it('draws no just-seen band, teaser or source chips: one source button in the body at most', () => {
    tried.decision = decision('ESCALATE');
    const { container } = after();
    const zones = Array.from(container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'));
    const pressables = zones.flatMap((zone) => Array.from(zone.querySelectorAll('button, a[href]')));
    expect(pressables).toHaveLength(1);
    expect(pressables[0]).toHaveTextContent(word('frame.source.open'));
    expect(container.textContent ?? '').not.toMatch(/run-[0-9a-f]{6,}/);
  });
});
