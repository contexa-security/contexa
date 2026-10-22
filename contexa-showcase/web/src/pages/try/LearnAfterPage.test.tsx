import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import LearnAfterPage from './LearnAfterPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

interface Check {
  readonly answered: boolean;
  readonly reissue_outcome: string | null;
}

/** A stored request as the screen reads it: Contexa's judgment, its identity check and the run's learned counts. */
function anatomy(finalAction: string, before: number, after: number, check: Check | null = null) {
  return {
    interpretation: { recorded: { finalAction } },
    recovery: check ? { challenge: check, release: null } : null,
    figures: { baselineBefore: before, baselineAfter: after },
  };
}

const PASSED: Check = { answered: true, reissue_outcome: 'DELIVERED' };

interface Server {
  runs: { runId: string; scenarioKey: string }[];
  measured: Record<string, { middleRun: string | null; resumed: { runId: string } | null }>;
  anatomies: Record<string, unknown>;
  actEnd: unknown;
}

const server: Server = { runs: [], measured: {}, anatomies: {}, actEnd: null };

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(body === null ? null : JSON.stringify(body), { status }));
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  Object.assign(server, { runs: [], measured: {}, anatomies: {}, actEnd: null });
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const journey = {
        state: { route: 'DEFAULT', act: 3, step: 'learn-after', differences: [6] },
        runs: server.runs.map((run) => ({ ...run, status: 'COMPLETED', lab: false })),
        predictions: [],
      };
      const stored = /^\/api\/runs\/([^/]+)\/steps\/(\d+)\/anatomy$/.exec(url);
      if (stored) {
        const body = server.anatomies[`${stored[1]}/${stored[2]}`];
        return body === undefined ? json(null, 404) : json(body);
      }
      const measured = /^\/api\/cases\/([^/]+)\/measured$/.exec(url);
      if (measured) {
        const body = server.measured[measured[1] ?? ''];
        return body === undefined ? json(null, 404) : json({ caseKey: measured[1], list: [], ...body });
      }
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': journey,
        '/api/journey/act-end?act=3': server.actEnd,
        '/api/lab/options': {
          employees: [],
          timeSlots: [],
          items: [],
          operations: [],
          cases: [{ key: 'A6T', requests: [{}, {}, {}, {}, {}] }],
          calls: [],
          assessmentReasons: [],
        },
      };
      const body = bodies[url];
      return body === undefined || body === null ? json(null, 404) : json(body);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** Try 3's real work, every request passed, as one stored run. */
function storeAllowed(runId: string, before: number, after: number) {
  for (const stepNo of [1, 2, 3, 4, 5]) {
    server.anatomies[`${runId}/${stepNo}`] = anatomy('ALLOW', before, after);
  }
}

function renderScreen(path: string, ending: boolean) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[path]}>
        <LearnAfterPage ending={ending} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function lines(): Promise<readonly string[]> {
  const list = await screen.findByRole('list', { name: word('screen.3-4.title') });
  return within(list)
    .getAllByRole('listitem')
    .map((item) => item.textContent ?? '');
}

function zone(container: HTMLElement, name: string): HTMLElement {
  return required(container.querySelector<HTMLElement>(`[data-zone="${name}"]`), name);
}

/**
 * Screen 3-4 (화면재편 T7): four lines of what Contexa learns and what not, each with the learned requests of a real run
 * of that kind (the visitor's own, else an earlier real request, as the source line says), and one warning line.
 */
describe('what it learns and what not', () => {
  it.each([
    { allow: [24, 29], check: [24, 25], stop: [24, 24], shown: ['24', '29', '25'] },
    { allow: [1200, 1205], check: [1200, 1201], stop: [1200, 1200], shown: ['1,200', '1,205', '1,201'] },
  ])("shows every line from the visitor's own runs ($shown.1)", async (record) => {
    const [from = '', allowTo = '', checkTo = ''] = record.shown;
    server.runs = [
      { runId: 'run-own-1', scenarioKey: 'A3' },
      { runId: 'run-own-2', scenarioKey: 'A3T' },
      { runId: 'run-own-3', scenarioKey: 'A6T' },
    ];
    storeAllowed('run-own-3', record.allow[0] ?? 0, record.allow[1] ?? 0);
    server.anatomies['run-own-2/1'] = anatomy(
      'CHALLENGE',
      record.check[0] ?? 0,
      record.check[1] ?? 0,
      PASSED,
    );
    server.anatomies['run-own-1/1'] = anatomy('ESCALATE', record.stop[0] ?? 0, record.stop[1] ?? 0);
    const { container } = renderScreen('/try/summary/learning', false);

    const [allow, checked, stopped, released] = await lines();
    expect(allow).toContain(word('p3.after.kind.allow'));
    expect(allow).toContain(word('p3.after.rule.allow'));
    expect(allow).toContain(fill('p3.stack.learned.changed', { from, to: allowTo }));
    expect(checked).toContain(word('p3.after.rule.checked'));
    expect(checked).toContain(fill('p3.stack.learned.changed', { from, to: checkTo }));
    expect(stopped).toContain(word('p3.after.rule.stopped'));
    expect(stopped).toContain(fill('p3.stack.learned.same', { from }));
    expect(released).toContain(word('p3.after.rule.released'));
    expect(released).toContain(word('p3.after.value.set'));
    // V-14: a release learns the request only when its facts were kept (a forced block keeps none, 2-6).
    expect(word('p3.after.rule.released')).toContain('사실이 남아 있으면');

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.3-4.title'));
    expect(zone(container, 'title')).toHaveTextContent(word('screen.3-4.guide'));
    // V-36: only a stopped attack stays out of the usual; the warning below says a passed one can be learned.
    expect(word('screen.3-4.guide')).toContain('막힌 공격');
    expect(screen.getByText(word('p3.after.warning'))).toBeInTheDocument();
    expect(zone(container, 'source')).toHaveTextContent(word('p3.after.source.own'));
    expect(screen.getByRole('link', { name: word('more.toHub') })).toHaveAttribute(
      'href',
      '/more',
    );
    // Nothing in the body to press; the old frame's lines are gone.
    expect(zone(container, 'body').querySelectorAll('a, button, summary, details')).toHaveLength(0);
    const text = document.body.textContent ?? '';
    for (const key of ['learnAfter.next', 'learnAfter.measured', 'learnAfter.core', 'justSaw.learnAfter']) {
      // Old keys may be removed from the dictionaries later (R9); a removed key is gone from the screen too.
      const old = KO[key];
      if (old !== undefined) {
        expect(text, key).not.toContain(old);
      }
    }
  });

  it("takes an earlier record when the visitor's run is not of the line's kind, and says the source is mixed", async () => {
    server.runs = [
      { runId: 'run-own-1', scenarioKey: 'A3' },
      { runId: 'run-own-2', scenarioKey: 'A3T' },
      { runId: 'run-own-3', scenarioKey: 'A6T' },
    ];
    storeAllowed('run-own-3', 24, 29);
    // The visitor's real-employee run passed without a check; the earlier one that passed a check is shown.
    server.anatomies['run-own-2/1'] = anatomy('ALLOW', 24, 25);
    server.measured['A3T'] = { middleRun: 'run-a3t', resumed: { runId: 'run-checked' } };
    server.anatomies['run-checked/1'] = anatomy('CHALLENGE', 30, 31, PASSED);
    server.anatomies['run-own-1/1'] = anatomy('ESCALATE', 24, 24);
    const { container } = renderScreen('/try/summary/learning', false);

    const [, checked] = await lines();
    expect(checked).toContain(fill('p3.stack.learned.changed', { from: '30', to: '31' }));
    expect(zone(container, 'source')).toHaveTextContent(word('p3.after.source.mixed'));
  });

  it('shows the earlier records when the visitor sent nothing, and says so', async () => {
    server.measured['A6T'] = { middleRun: 'run-a6t', resumed: null };
    server.measured['A3T'] = { middleRun: 'run-a3t', resumed: { runId: 'run-checked' } };
    server.measured['A3'] = { middleRun: 'run-a3', resumed: null };
    storeAllowed('run-a6t', 24, 29);
    server.anatomies['run-checked/1'] = anatomy('CHALLENGE', 24, 25, PASSED);
    server.anatomies['run-a3/1'] = anatomy('ESCALATE', 24, 24);
    const { container } = renderScreen('/try/summary/learning', false);

    const [allow, , stopped] = await lines();
    expect(allow).toContain(fill('p3.stack.learned.changed', { from: '24', to: '29' }));
    expect(stopped).toContain(fill('p3.stack.learned.same', { from: '24' }));
    expect(zone(container, 'source')).toHaveTextContent(word('frame.source.earlier'));
  });

  it('says when no run of a kind exists rather than showing another kind', async () => {
    server.measured['A6T'] = { middleRun: 'run-a6t', resumed: null };
    server.measured['A3T'] = { middleRun: 'run-a3t', resumed: null };
    // The measured run of the stolen account was let through: it is not a stopped request.
    server.measured['A3'] = { middleRun: 'run-a3', resumed: null };
    storeAllowed('run-a6t', 24, 29);
    server.anatomies['run-a3/1'] = anatomy('ALLOW', 24, 25);
    renderScreen('/try/summary/learning', false);

    const [, checked, stopped] = await lines();
    expect(checked).toContain(word('p3.after.value.none'));
    expect(stopped).toContain(word('p3.after.value.none'));
    expect(stopped).not.toContain(fill('p3.stack.learned.changed', { from: '24', to: '25' }));
  });
});

/** Screen 3-5 (T8): the part's wrap-up, the visitor's learning sentence from the server and the differences. */
