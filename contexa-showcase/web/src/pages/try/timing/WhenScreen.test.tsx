import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import { measuredCase, portalStub } from '../../../test/timingFixture';
import WhenScreen from './WhenScreen';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

/** Two measurements with different values, so a cost that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'the current measurement',
    work: { min: 3447, max: 4011 },
    out: { min: 4831, max: 4831 },
    shown: { seconds: '3.4~4.0', items: '4,831' },
  },
  {
    name: 'another setting',
    work: { min: 9120, max: 9120 },
    out: { min: 1200, max: 2400 },
    shown: { seconds: '9.1', items: '1,200~2,400' },
  },
] as const;

let bodies: Record<string, unknown> = {};

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
      <MemoryRouter initialEntries={['/try/timing/when']}>
        <WhenScreen />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function questions(): readonly HTMLElement[] {
  const flow = screen.getByRole('list', { name: word('p4.when.figure') });
  return Array.from(flow.querySelectorAll<HTMLElement>(':scope > li'));
}

/** Screen 4-3 (화면재편 T7): two questions that choose the way, each way with the work it fits and its recorded cost. */
describe('which way for which work', () => {
  it.each(RECORDS)('leads each yes to its way, with the cost as recorded ($name)', async (record) => {
    bodies = {
      '/api/cases/A3T/measured': measuredCase('A3T', { results: { PASSED: 5 }, responseMs: record.work }),
      '/api/cases/A3A/measured': measuredCase('A3A', { results: { PARTLY_STOPPED: 5 }, exposedItems: record.out }),
    };
    const { container } = open();
    const syncCost = fill('p4.when.syncCost', { seconds: record.shown.seconds });
    expect(await screen.findByText(syncCost)).toBeInTheDocument();

    const [first, second] = questions().map((question) => within(question));
    expect(first?.getByText(word('p4.when.q1'))).toBeInTheDocument();
    const sync = required(first, 'the first question').getByRole('region', { name: word('p4.mode.sync') });
    expect(within(sync).getByText(word('p4.when.syncWork'))).toBeInTheDocument();
    expect(within(sync).getByText(syncCost)).toBeInTheDocument();
    expect(first?.getByText(word('p4.when.no'))).toBeInTheDocument();

    expect(second?.getByText(word('p4.when.q2'))).toBeInTheDocument();
    const async = required(second, 'the second question').getByRole('region', { name: word('p4.mode.async') });
    expect(within(async).getByText(word('p4.when.asyncWork'))).toBeInTheDocument();
    expect(within(async).getByText(fill('p4.when.asyncCost', { items: record.shown.items }))).toBeInTheDocument();
    // V-53: the second question has its own "no"; P-18: the plain word '아니요'.
    expect(second?.queryByText(word('p4.when.no'))).not.toBeInTheDocument();
    expect(second?.getByText(word('p4.when.no2'))).toBeInTheDocument();
    for (const key of ['p4.when.no', 'p4.when.no2']) {
      expect(word(key).startsWith('아니요')).toBe(true);
    }

    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.measured'));
  });

  it('keeps the flow without costs or a source line when there is no record, and leads on to the wrap-up', async () => {
    const { container } = open();
    expect(await screen.findByText(word('p4.when.syncWork'))).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.4-3.title'));
    expect(screen.getByText(word('screen.4-3.guide'))).toBeInTheDocument();
    expect(screen.getByText(word('p4.when.asyncWork'))).toBeInTheDocument();
    expect(document.body.textContent ?? '').not.toContain(word('p4.when.syncCost').split('{{')[0] ?? '');
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
    expect(screen.getByRole('link', { name: word('more.toHub') })).toHaveAttribute('href', '/more');
  });

  it('draws no just-seen band, demo settings or caution: nothing to press in the body', async () => {
    const { container } = open();
    await screen.findByText(word('p4.when.syncWork'));
    const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
    expect(body.querySelectorAll('a, button, summary, details')).toHaveLength(0);
    const text = document.body.textContent ?? '';
    for (const key of ['timing.when.demo', 'timing.when.caution', 'timing.when.syncFits', 'timing.when.asyncFits']) {
      expect(text).not.toContain(word(key));
    }
    expect(text).not.toContain('@Protectable');
  });
});
