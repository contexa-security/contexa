import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PublicSettingsView } from '../../api/settings';
import { CONTROL_ORDER } from '../../domain/verdict';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import ApproachesPage from './ApproachesPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

/** The running settings as the portal's /api/settings gives them (the values are this test's own). */
const SETTINGS: PublicSettingsView = {
  waf: { image: 'waf-image:test', ruleSet: 'rule set test' },
  permission: { roleRules: ['GET /api/test [ADMIN]'] },
  threshold: { nightStart: '21:30', nightEnd: '05:30', volumeLimit: 321, dormantWindowDays: 12 },
  businessRecord: {
    exportPolicyKey: 'POLICY_TEST',
    assignedExportLimit: 77,
    ticketAndOncallExempt: true,
    historyWindowDays: 9,
    exportHistoryWindowDays: 8,
    accessPolicies: [],
  },
  engine: {
    chatModel: 'primary-model',
    effectiveMode: 'ENFORCE',
    inspectorConditions: 11,
    layer1Model: 'model-under-test',
    layer2Model: 'layer-two-model',
  },
  retention: { behaviorDays: 5, promptOriginalDays: 6 },
  ruleVersion: 'v-test',
};

let settings: { readonly status: number; readonly body: unknown };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, { readonly status: number; readonly body: unknown }> = {
        '/api/settings': settings,
        '/api/visitor': { status: 200, body: { predictions: {} } },
        '/api/journey': {
          status: 200,
          body: {
            state: { route: 'DEFAULT', act: 5, step: 'g3-five', differences: [] },
            runs: [],
            predictions: [],
          },
        },
      };
      const { status, body } = bodies[url] ?? { status: 404, body: null };
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
  settings = { status: 200, body: SETTINGS };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/intro/approaches']}>
        <ApproachesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Screen 5-0, the cover of part 5 (화면재편-기획안 7절, T1): the part map, five lines, where they sit, one chip. */
describe('the five methods', () => {
  it('names each method once with its industry term, what it sees and what it misses', () => {
    open();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.5-0.title'));
    expect(screen.getByText(word('screen.5-0.guide'))).toBeInTheDocument();
    const rows = within(screen.getByRole('list', { name: word('p5.five.list') })).getAllByRole('listitem');
    expect(rows).toHaveLength(CONTROL_ORDER.length);
    CONTROL_ORDER.forEach((control, index) => {
      const row = required(rows[index], control);
      expect(row).toHaveTextContent(word(`control.${control}.name`));
      expect(row).toHaveTextContent(word(`p5.five.term.${control}`));
      expect(row).toHaveTextContent(word(`p5.five.${control}.sees`));
      expect(row).toHaveTextContent(word(`p5.five.${control}.misses`));
    });
  });

  it('leaves the part map to the briefing of the part (T0, 기획안 15절)', () => {
    open();
    expect(screen.queryByRole('list', { name: word('frame.map') })).not.toBeInTheDocument();
  });

  it('draws where they sit in one line: the web firewall outside the app, the rest inside before the task', () => {
    open();
    const path = screen.getByRole('list', { name: word('p5.five.where.figure') });
    const stops = Array.from(path.querySelectorAll(':scope > li'), (item) => item.textContent ?? '');
    expect(stops).toEqual([
      word('p5.five.where.request'),
      word('p5.five.where.outside') + word('control.A.name'),
      [
        word('p5.five.where.inside'),
        word('control.B.name'),
        word('control.C1.name'),
        word('control.C2.name'),
        word('control.D.name'),
        word('p5.five.where.task'),
      ].join(''),
    ]);
    expect(screen.getByText(word('p5.five.where.honest'))).toBeInTheDocument();
    // V-54: the figure says it is where each sits in a real deployment (the demo's copies are the caption).
    const figure = required(path.closest('figure'), 'the figure');
    expect(within(figure).getByText(word('p5.five.where.title'))).toBeInTheDocument();
    expect(word('p5.five.where.title')).toContain('실제 도입');
  });

  it('keeps one thing to press in the body, the details chip, and the main button to 5-1', () => {
    const { container } = open();
    const zones = Array.from(
      container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
    );
    const pressables = zones.flatMap((zone) => Array.from(zone.querySelectorAll('button, a[href]')));
    expect(pressables).toHaveLength(1);
    expect(pressables[0]).toHaveTextContent(word('p5.five.open'));
    // V-54: no request is judged here, so the chip opens the published criteria, not a judgment's reasons.
    expect(word('p5.five.open')).not.toBe(word('frame.detail'));
    // P-17: what Contexa misses, in plain words, and where it is published.
    expect(word('p5.five.D.misses')).toContain('한계');
    expect(screen.getByRole('link', { name: word('more.toHub') })).toHaveAttribute(
      'href',
      '/more',
    );
    // Gone from the screen: the old title, the hint, the limits chip and the old words.
    const text = document.body.textContent ?? '';
    for (const key of [
      'approaches.title',
      'approaches.hint',
      'approaches.limits',
      'where.title',
      'where.code',
    ]) {
      expect(text, key).not.toContain(word(key));
    }
  });

  it("opens one window with each method's settings as the running stack publishes them", async () => {
    open();
    fireEvent.click(screen.getByRole('button', { name: word('p5.five.open') }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: word('p5.five.settings') })).toBeInTheDocument();
    // Contexa first; its model is the stack's value.
    expect(within(dialog).getByRole('button', { name: word('control.D.name') })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(await within(dialog).findByText('model-under-test')).toBeInTheDocument();
    // 판정층 E-8c: each analysis layer's own model, as the stack states it.
    expect(within(dialog).getByText(word('settings.D.layer1Model'))).toBeInTheDocument();
    expect(within(dialog).getByText('layer-two-model')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: word('control.C1.name') }));
    expect(
      within(dialog).getByText(fill('settings.C1.nightValue', { from: '21:30', to: '05:30' })),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText('model-under-test')).not.toBeInTheDocument();
  });

  it('says the settings could not be read when the stack does not answer', async () => {
    settings = { status: 404, body: null };
    open();
    fireEvent.click(screen.getByRole('button', { name: word('p5.five.open') }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(word('settings.unavailable'))).toBeInTheDocument();
  });
});
