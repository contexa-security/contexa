import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { MeasuredCase } from '../../../api/measured';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import { measuredCase, portalStub } from '../../../test/timingFixture';
import CompareScreen from './CompareScreen';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

/** The four measured cases as the server counted them (the attack and normal work, each sent both ways). */
function cases(changes: Partial<Record<'A3' | 'A3A' | 'A3T' | 'A3TA', MeasuredCase | null>> = {}) {
  const base: Record<string, MeasuredCase | null> = {
    A3: measuredCase('A3', { results: { STOPPED: 5 }, exposedItems: { min: 0, max: 0 }, responseMs: { min: 3754, max: 7559 } }),
    A3A: measuredCase('A3A', { results: { PARTLY_STOPPED: 5 }, exposedItems: { min: 4831, max: 4831 }, responseMs: { min: 46, max: 70 } }),
    A3T: measuredCase('A3T', { results: { PASSED: 5 }, exposedItems: { min: 4831, max: 4831 }, responseMs: { min: 3447, max: 4011 } }),
    A3TA: measuredCase('A3TA', { results: { PASSED: 5 }, exposedItems: { min: 4831, max: 4831 }, responseMs: { min: 36, max: 83 } }),
    ...changes,
  };
  return Object.fromEntries(
    Object.entries(base).map(([key, value]) => [`/api/cases/${key}/measured`, value]),
  );
}

let bodies: Record<string, unknown> = {};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  bodies = cases();
  vi.stubGlobal('fetch', vi.fn(portalStub(() => bodies)));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/try/timing/compare']}>
        <CompareScreen />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The cells of a row, by the row's name: each cell's result word and its one value. */
async function row(name: string): Promise<readonly string[]> {
  const header = await screen.findByRole('rowheader', { name });
  const cells = required(header.closest('tr'), 'the row').querySelectorAll('td');
  return Array.from(cells, (cell) => cell.textContent ?? '');
}

/** Screen 4-2 (화면재편 T5): the title the results pick and one two by two of the server's counts. */
describe('the two ways compared', () => {
  it("states the trade-off when the results make it true, each cell the server's result and range", async () => {
    const { container } = open();
    const [attackSync, attackAsync] = await row(word('p4.compare.attack'));
    expect(attackSync).toBe(word('p1.result.word.STOPPED') + fill('p4.items', { items: '0' }));
    // V-06: what went out is said as a sentence: the first request's records, then blocked from the next request.
    expect(attackAsync).toBe(word('p1.result.word.PARTLY_STOPPED') + fill('p4.compare.leaked', { items: '4,831' }));
    const [workSync, workAsync] = await row(word('p4.compare.work'));
    expect(workSync).toBe(word('p1.result.word.PASSED') + fill('p4.response', { seconds: '3.4~4.0' }));
    expect(workAsync).toBe(word('p1.result.word.PASSED') + fill('p4.response', { seconds: '0.04~0.08' }));
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.4-2.title'));
    expect(screen.getByText(word('screen.4-2.guide'))).toBeInTheDocument();
    // P-24: plain words for the trade-off.
    expect(word('screen.4-2.title')).toContain('장단점');
    // The one emphasis: the result that let records out, by word and color together.
    expect(screen.getByText(word('p1.result.word.PARTLY_STOPPED'))).toHaveAttribute('data-wrong');
    expect(screen.getByText(word('p1.result.word.STOPPED'))).not.toHaveAttribute('data-wrong');
    const source = required(container.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.measured'));
    expect(screen.getByRole('link', { name: word('frame.nextNamed').replace('{{name}}', word('more.name.sync-when')) })).toHaveAttribute('href', '/try/timing/when');
    const body = required(container.querySelector<HTMLElement>('[data-zone="body"]'), 'the body');
    expect(body.querySelectorAll('a, button')).toHaveLength(0);
  });

  it("marks the cost of stopping before the response: normal work's wait, and only that value (L-10)", async () => {
    open();
    const wait = await screen.findByText(fill('p4.response', { seconds: '3.4~4.0' }));
    expect(wait).toHaveAttribute('data-cost');
    expect(screen.getByText(fill('p4.response', { seconds: '0.04~0.08' }))).not.toHaveAttribute('data-cost');
    expect(screen.getByText(fill('p4.items', { items: '0' }))).not.toHaveAttribute('data-cost');
    expect(screen.getByText(fill('p4.compare.leaked', { items: '4,831' }))).not.toHaveAttribute('data-cost');
  });

  it('writes a range only where the runs differ, one value where they are the same', async () => {
    bodies = cases({
      A3A: measuredCase('A3A', { results: { PARTLY_STOPPED: 5 }, exposedItems: { min: 1200, max: 2400 }, responseMs: null }),
      A3TA: measuredCase('A3TA', { results: { PASSED: 5 }, responseMs: { min: 57, max: 57 } }),
    });
    open();
    expect((await row(word('p4.compare.attack')))[1]).toContain(fill('p4.compare.leaked', { items: '1,200~2,400' }));
    expect((await row(word('p4.compare.work')))[1]).toContain(fill('p4.response', { seconds: '0.06' }));
  });

  it('only names the table when the results do not show the trade-off', async () => {
    bodies = cases({ A3A: measuredCase('A3A', { results: { STOPPED: 5 }, exposedItems: { min: 0, max: 0 } }) });
    open();
    await row(word('p4.compare.attack'));
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('p4.compare.title.other'));
  });

  it('says the result differed between sends instead of picking one', async () => {
    bodies = cases({
      A3: measuredCase('A3', { results: { STOPPED: 3, PARTLY_STOPPED: 2 }, allSame: false, exposedItems: { min: 0, max: 4831 } }),
    });
    open();
    const [attackSync] = await row(word('p4.compare.attack'));
    expect(attackSync).toContain(word('p4.compare.mixed'));
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('p4.compare.title.other'));
  });

  it('marks a cell without a record and names the table only', async () => {
    bodies = cases({ A3TA: null });
    open();
    const [, workAsync] = await row(word('p4.compare.work'));
    expect(workAsync).toBe(word('p4.none'));
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('p4.compare.title.other'));
  });

  it('says there is nothing to compare yet when no case has a record, without a table or a source line', async () => {
    bodies = cases({ A3: null, A3A: null, A3T: null, A3TA: null });
    const { container } = open();
    expect(await screen.findByText(word('p4.compare.none'))).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
  });

  it('draws no code notation, mode hints or trade-off boxes', async () => {
    open();
    const table = await screen.findByRole('table');
    expect(within(table).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual([
      word('p4.compare.situation'),
      word('p4.mode.sync'),
      word('p4.mode.async'),
    ]);
    const text = document.body.textContent ?? '';
    expect(text).not.toContain('@Protectable');
    for (const key of ['timing.compare.syncHint', 'timing.compare.asyncHint', 'timing.compare.syncTrade', 'timing.compare.asyncTrade']) {
      expect(text).not.toContain(word(key));
    }
  });
});
