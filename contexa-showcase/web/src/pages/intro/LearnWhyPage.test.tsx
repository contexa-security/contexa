import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import LearnWhyPage from './LearnWhyPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

/** The engine's learned requests per hour: 24 values, the given counts at the given hours. */
function hoursWith(counts: Readonly<Record<number, number>>): number[] {
  return Array.from({ length: 24 }, (_, hour) => counts[hour] ?? 0);
}

/** The baseline card as the portal gives it (BaselineCard.View); only the learned part is read on this screen. */
function baselineOf(requests: number, hours: readonly number[]) {
  return {
    employeeKey: 'adm-a',
    displayName: 'Administrator A',
    department: 'IT administration',
    templateId: 'tpl-adm-a-1',
    capturedAt: '2026-10-17T07:25:49Z',
    learned: {
      requests,
      hours,
      weekdays: [5, 4, 5, 5, 5, 0, 0],
      networks: ['10.40.12.0/24'],
      devices: ['WINDOWS', 'Chrome/140'],
    },
    taught: {
      reads: 15,
      downloads: 5,
      exports: 5,
      exportItemsMin: 14,
      exportItemsMax: 29,
      projects: { 'PLM-OPS': 25 },
      from: '2026-09-23T11:48:00Z',
      to: '2026-09-29T16:04:00Z',
    },
    requests: [],
    sent: requests + 1,
    allowed: requests,
    hours: null,
  };
}

/** The lab options: try 1's case, its employee and the case's time slot (the request's hour comes from here). */
const OPTIONS = {
  employees: [{ key: 'adm-a', displayName: 'Administrator A', officeNetwork: '10.40.12.0/24' }],
  projects: [],
  timeSlots: [{ slot: 'DAWN', representativeTime: '03:17' }],
  items: [],
  operations: [],
  cases: [{ key: 'A3', conditions: { employee: 'adm-a', timeSlot: 'DAWN' }, requests: [{ items: 4831 }] }],
  calls: [],
  assessmentReasons: [],
};

let baseline: unknown;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/journey': {
          state: { route: 'DEFAULT', act: 3, step: 'g-learn-why', differences: [] },
          runs: [],
          predictions: [],
        },
        '/api/lab/options': OPTIONS,
        '/api/live/baseline/adm-a': baseline,
      };
      const body = bodies[url];
      return Promise.resolve(
        new Response(body === undefined || body === null ? null : JSON.stringify(body), {
          status: body ? 200 : 404,
        }),
      );
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/intro/learning']}>
        <LearnWhyPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Two records with different values, so a panel that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'nothing learned at the hour',
    baseline: baselineOf(24, hoursWith({ 9: 2, 10: 3, 11: 6, 12: 2, 13: 4, 14: 4, 17: 3 })),
    line: () => fill('p3.why.known.zero', { n: '24' }),
  },
  {
    name: 'some learned at the hour',
    baseline: baselineOf(1234, hoursWith({ 3: 2, 10: 1232 })),
    line: () => fill('p3.why.known.some', { n: '1,234', at: '2' }),
  },
] as const;

/**
 * Screen 3-0, the cover of part 3 (화면재편 T1): the part map, the question, and the two panels; the panel with the
 * usual reads the learned count at the request's hour from the record.
 */
describe('part 3 cover', () => {
  it.each(RECORDS)(
    'says how many learned requests came at the request hour, as recorded ($name)',
    async (record) => {
      baseline = record.baseline;
      open();
      const known = await screen.findByRole('region', { name: word('p3.why.known.title') });
      expect(await within(known).findByText(record.line())).toBeInTheDocument();
      expect(within(known).getByText(word('p3.why.mark'))).toBeInTheDocument();
      const unknown = screen.getByRole('region', { name: word('p3.why.unknown.title') });
      expect(within(unknown).getByText(word('p3.why.unknown.text'))).toBeInTheDocument();
    },
  );

  it('keeps only the part map, the question and the two panels, with one source line and the next question', async () => {
    baseline = RECORDS[0].baseline;
    const { container } = open();
    await screen.findByText(RECORDS[0].line());

    // The question names the case's own hour (IN-6).
    expect(
      screen.getByRole('heading', { level: 1, name: word('screen.3-0.title').replace('{{clock}}', '03:17') }),
    ).toBeInTheDocument();
    expect(screen.getByText(word('screen.3-0.guide'))).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: word('frame.map') })).not.toBeInTheDocument();
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.learned'));
    expect(
      screen.getByRole('link', {
        name: word('frame.nextNamed').replace('{{name}}', word('more.name.g-learned')),
      }),
    ).toHaveAttribute('href', '/intro/learning/learned');
    // Nothing to press in the body: the one way on is the main button.
    const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
    expect(body.querySelectorAll('a, button, summary, details')).toHaveLength(0);

    // Gone from the cover: the closing line and the demo / real-service tags.
    const text = document.body.textContent ?? '';
    for (const key of ['learnWhy.so', 'learnWhy.demo.text', 'learnWhy.real.text', 'learnWhy.source']) {
      expect(text).not.toContain(word(key).replace(/\{\{\w+\}\}/g, ''));
    }
  });

  it('says the record could not be read instead of drawing an empty chart', async () => {
    baseline = null;
    const { container } = open();
    expect(await screen.findByText(word('p3.learned.none'))).toBeInTheDocument();
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
  });
});
