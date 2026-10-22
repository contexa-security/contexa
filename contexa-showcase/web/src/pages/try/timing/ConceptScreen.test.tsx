import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import { measuredCase, measuredRun, portalStub } from '../../../test/timingFixture';
import ConceptScreen from './ConceptScreen';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

/**
 * Two measurements with different values, so a row that shows a constant fails one of them. Each case lists a run
 * before its middle one, so a row that takes the first run instead of the server's middle fails too.
 */
const RECORDS = [
  {
    name: 'held for review',
    sync: { other: { exposedItems: 0, responseMs: 7559, analysisMs: 7478 }, middle: { exposedItems: 0, responseMs: 4073, analysisMs: 3983 } },
    async: { other: { exposedItems: 4831, responseMs: 70, analysisMs: 7382 }, middle: { exposedItems: 4831, responseMs: 46, analysisMs: 4199 } },
    shown: { syncJudge: '4.0', syncSeconds: '4.1', syncItems: '0', asyncSeconds: '0.05', asyncItems: '4,831', judge: '4.2' },
  },
  {
    name: 'another setting',
    sync: { other: { exposedItems: 0, responseMs: 3754, analysisMs: 3690 }, middle: { exposedItems: 0, responseMs: 9120, analysisMs: 8960 } },
    async: { other: { exposedItems: 1200, responseMs: 58, analysisMs: 3954 }, middle: { exposedItems: 1200, responseMs: 83, analysisMs: 6810 } },
    shown: { syncJudge: '9.0', syncSeconds: '9.1', syncItems: '0', asyncSeconds: '0.08', asyncItems: '1,200', judge: '6.8' },
  },
] as const;

let bodies: Record<string, unknown> = {};

type RunValues = Parameters<typeof measuredRun>[1];

function caseOf(key: string, runs: { readonly other: RunValues; readonly middle: RunValues }) {
  return measuredCase(key, {
    results: { STOPPED: 5 },
    list: [measuredRun(`run-${key}-other`, runs.other), measuredRun(`run-${key}-middle`, runs.middle)],
    middleRun: `run-${key}-middle`,
  });
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = {};
  vi.stubGlobal('fetch', vi.fn(portalStub(() => bodies)));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/try/timing/concept']}>
        <ConceptScreen />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function rows(): readonly string[] {
  const figure = screen.getByRole('list', { name: word('p4.concept.figure') });
  return Array.from(figure.querySelectorAll(':scope > li'), (item) => item.textContent ?? '');
}

/** Screen 4-0, the cover of part 4 (화면재편 T1): the part map and the same export in time order, both ways. */
describe('part 4 cover', () => {
  it.each(RECORDS)("draws each way from the server's middle run ($name)", async (record) => {
    bodies = { '/api/cases/A3/measured': caseOf('A3', record.sync), '/api/cases/A3A/measured': caseOf('A3A', record.async) };
    open();
    await screen.findByRole('list', { name: word('p4.concept.figure') });
    const [sync, async] = rows();
    expect(sync).toContain(word('p4.mode.sync'));
    // V-39: the same words as the screen after it, judgment time and answer time.
    expect(sync).toContain(fill('p4.concept.sync', { judge: record.shown.syncJudge, seconds: record.shown.syncSeconds }));
    expect(sync).toContain(fill('p4.items', { items: record.shown.syncItems }));
    expect(async).toContain(word('p4.mode.async'));
    expect(async).toContain(fill('p4.concept.async', { seconds: record.shown.asyncSeconds }));
    expect(async).toContain(fill('p4.items', { items: record.shown.asyncItems }));
    expect(async).toContain(fill('p4.concept.judge', { seconds: record.shown.judge }));

    // B-10: what went out stands out where records left; the time line has its scale and its legend.
    const [syncRow, asyncRow] = Array.from(
      screen.getByRole('list', { name: word('p4.concept.figure') }).querySelectorAll<HTMLElement>(':scope > li'),
    );
    expect(screen.getAllByText(fill('p4.items', { items: record.shown.asyncItems }))[0]).toHaveAttribute('data-out');
    expect(required(syncRow, 'the sync row').querySelector('[data-out]')).toBeNull();
    expect(required(asyncRow, 'the async row').querySelector('[data-out]')).not.toBeNull();
    const axis = required(document.querySelector<HTMLElement>('[data-axis]'), 'the time scale');
    for (const tick of ['0', record.shown.syncSeconds, record.shown.judge]) {
      expect(axis).toHaveTextContent(fill('p4.concept.tick', { seconds: tick }));
    }
    const legend = screen.getByRole('list', { name: word('p4.concept.legend') });
    expect(Array.from(legend.querySelectorAll('li'), (item) => item.textContent)).toEqual([
      word('p4.concept.legend.held'),
      word('p4.concept.legend.out'),
      word('p4.concept.legend.judge'),
    ]);
  });

  it('keeps only the two rows, with one source line and the next question', async () => {
    bodies = { '/api/cases/A3/measured': caseOf('A3', RECORDS[0].sync), '/api/cases/A3A/measured': caseOf('A3A', RECORDS[0].async) };
    const { container } = open();
    await screen.findByRole('list', { name: word('p4.concept.figure') });
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.4-0.title'));
    expect(screen.getByText(word('screen.4-0.guide'))).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: word('frame.map') })).not.toBeInTheDocument();
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('p4.source.middle'));
    // P-24, V-39: the two rows are separate runs, each the median of its way's measured judgment times.
    expect(word('p4.source.middle')).toContain('중앙값');
    expect(source.querySelectorAll('button, a')).toHaveLength(0);
    const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
    expect(body.querySelectorAll('a, button, summary, details, table')).toHaveLength(0);
    expect(screen.getByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.sync-try')) })).toHaveAttribute('href', '/try/timing/try');
    // Gone: the business-code notation (5-3) and the old meanings boxes; the legend is back with B-10.
    const text = document.body.textContent ?? '';
    expect(text).not.toContain('@Protectable');
    for (const key of ['timing.concept.syncMeans', 'timing.concept.asyncMeans']) {
      expect(text).not.toContain(word(key));
    }
    expect(text).not.toMatch(/run-[0-9a-f]{6,}/);
  });

  it('says there is no record yet when one of the two ways has none, without a figure or a source line', async () => {
    bodies = { '/api/cases/A3/measured': caseOf('A3', RECORDS[0].sync) };
    const { container } = open();
    expect(await screen.findByText(word('p4.concept.none'))).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: word('p4.concept.figure') })).not.toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
  });
});
