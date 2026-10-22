import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import ko from '../i18n/ko.json';
import { required } from '../test/required';
import AdoptPage from './AdoptPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

type Answer = { readonly status: number; readonly body: unknown };

let answers: Record<string, Answer>;

function ok(body: unknown): Answer {
  return { status: 200, body };
}

const MISSING: Answer = { status: 404, body: null };

function settings(
  retention: { readonly behaviorDays: number | null; readonly promptOriginalDays: number },
  sealedEvidence: { readonly samplePercent: number | null; readonly cleanPeriodDays: number | null } | null,
  effectiveMode = 'ENFORCE',
) {
  return {
    engine: { chatModel: 'm', effectiveMode, inspectorConditions: 18 },
    retention,
    sealedEvidence,
  };
}

function benchmark(normal: number, blocked: number, checked: number) {
  const rate = (hits: number, total: number) => ({
    hits,
    total,
    rate: null,
    low: null,
    high: null,
    preliminary: false,
  });
  return {
    controls: [
      { control: 'C1', falseBlock: rate(9, 9), friction: rate(0, 9) },
      { control: 'D', falseBlock: rate(blocked, normal), friction: rate(checked, normal) },
    ],
  };
}

function stats(
  decisions: number,
  actions: Readonly<Record<string, number>>,
  firstAt: string,
  lastAt: string,
) {
  return {
    runs: { completed: 1, failed: 0, today: 0, live: 0, firstAt, lastAt },
    engineActions: actions,
    engineDecisions: decisions,
  };
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  answers = {};
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, Answer> = {
        '/api/visitor': ok({ predictions: {} }),
        '/api/journey': ok({
          state: { route: 'DEFAULT', act: 0, step: 'hook', differences: [] },
          runs: [],
          predictions: [],
        }),
        ...answers,
      };
      const { status, body } = bodies[url] ?? MISSING;
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AdoptPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function zone(container: HTMLElement, name: string): HTMLElement {
  return required(container.querySelector<HTMLElement>(`[data-zone="${name}"]`), name);
}

function presses(container: HTMLElement): number {
  return Array.from(
    container.querySelectorAll('[data-zone="title"], [data-zone="body"], [data-zone="source"]'),
  ).flatMap((element) => Array.from(element.querySelectorAll('button, a[href]'))).length;
}

/** Two different records, so a cell that shows a constant fails one of them. */
const RECORDS = [
  {
    name: 'the demo settings',
    settings: settings(
      { behaviorDays: 400, promptOriginalDays: 90 },
      { samplePercent: 100, cleanPeriodDays: 90 },
    ),
    benchmark: benchmark(75, 0, 5),
    kept: { behavior: '400', original: '90' },
    seal: { days: '90', percent: '100' },
    counts: { normal: '75', blocked: '0', checked: '5' },
  },
  {
    name: 'other settings',
    settings: settings(
      { behaviorDays: 1200, promptOriginalDays: 30 },
      { samplePercent: 25, cleanPeriodDays: 14 },
    ),
    benchmark: benchmark(1500, 3, 41),
    kept: { behavior: '1,200', original: '30' },
    seal: { days: '14', percent: '25' },
    counts: { normal: '1,500', blocked: '3', checked: '41' },
  },
] as const;

/** The adopt space (화면재편-구현계획 5절 RO-4, RO-9): three views in the shared frame, kept within the limits. */
describe('adopting Contexa: what changes', () => {
  it.each(RECORDS)(
    'shows the three cells 5-3 left here, every number the server value ($name)',
    async (record) => {
      answers = { '/api/settings': ok(record.settings), '/api/benchmark': ok(record.benchmark) };
      const { container } = open('/adopt');
      expect(await screen.findByText(fill('space.r7.adopt.data.kept', record.kept))).toBeInTheDocument();
      expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
        word('space.r7.adopt.change.title'),
      );
      const names = Array.from(zone(container, 'body').querySelectorAll('dt'), (name) => name.textContent);
      expect(names).toEqual(['data', 'employee', 'admin'].map((cell) => word(`space.r7.adopt.name.${cell}`)));
      expect(screen.getByText(fill('space.r7.adopt.data.seal', record.seal))).toBeInTheDocument();
      // P-19: the seal said in plain words (what is kept unchangeable, how long it is kept, what is checked).
      for (const key of ['space.r7.adopt.data.seal', 'space.r7.adopt.data.sealPlain']) {
        expect(word(key)).toContain('고칠 수 없게');
        expect(word(key)).not.toContain('판단 입력');
        expect(word(key)).not.toContain('보존');
      }
      expect(
        await screen.findByText(fill('space.r7.adopt.employee.counts', record.counts)),
      ).toBeInTheDocument();
      expect(screen.getByText(word('space.r7.adopt.admin.what'))).toBeInTheDocument();
      expect(zone(container, 'source')).toHaveTextContent(word('space.r7.adopt.change.source'));
      // Nothing to press in the screen itself; the one way on names the next view's question.
      expect(presses(container)).toBe(0);
      expect(
        within(zone(container, 'actions')).getByRole('link', { name: word('space.r7.adopt.change.next') }),
      ).toHaveAttribute('href', '/adopt?step=attach');
      // The top bar names the space and the view, not the five parts.
      expect(zone(container, 'top')).toHaveTextContent(
        `${word('frame.space.adopt')} · ${word('space.r7.adopt.change.step')}`,
      );
      expect(container.querySelector('main')).toHaveAttribute('data-type', 'T7');
    },
  );

  it('says what the server does not give instead of a number', async () => {
    answers = {
      '/api/settings': ok(settings({ behaviorDays: null, promptOriginalDays: 90 }, null)),
      '/api/benchmark': MISSING,
    };
    const { container } = open('/adopt');
    expect(
      await screen.findByText(fill('space.r7.adopt.data.keptNoBehavior', { original: '90' })),
    ).toBeInTheDocument();
    expect(screen.getByText(word('space.r7.adopt.data.sealPlain'))).toBeInTheDocument();
    expect(screen.getByText(word('space.r7.adopt.employee.what'))).toBeInTheDocument();
    expect(container.textContent).not.toContain(word('space.r7.adopt.employee.counts').split('{{')[0] ?? '');
    expect(zone(container, 'source')).toHaveTextContent(word('space.r7.adopt.change.sourceSettings'));
  });

  it('says the retention could not be read when the settings do not answer', async () => {
    answers = { '/api/settings': MISSING, '/api/benchmark': ok(RECORDS[0].benchmark) };
    const { container } = open('/adopt');
    expect(await screen.findByText(word('space.r7.adopt.data.keptNone'))).toBeInTheDocument();
    expect(screen.getByText(word('space.r7.adopt.data.sealPlain'))).toBeInTheDocument();
    expect(
      await screen.findByText(fill('space.r7.adopt.employee.counts', RECORDS[0].counts)),
    ).toBeInTheDocument();
    expect(zone(container, 'source')).toHaveTextContent(word('frame.source.measured'));
  });
});

describe('adopting Contexa: adding it', () => {
  it('shows the real coordinates as code, and the examples and the repository to open', () => {
    const { container } = open('/adopt?step=attach');
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('space.r7.adopt.attach.title'));
    const code = screen.getByLabelText(word('space.r7.adopt.attach.code'));
    expect(code.tagName).toBe('PRE');
    expect(code).toHaveAttribute('data-original');
    expect(code).toHaveTextContent('implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"');
    expect(code).toHaveTextContent('@EnableAISecurity');
    expect(code).toHaveTextContent('@Protectable(sync = true)');
    expect(screen.getByText('sync = true').tagName).toBe('CODE');
    expect(screen.getByRole('link', { name: word('adopt.quickstart') })).toHaveAttribute(
      'href',
      'https://github.com/contexa73/contexa-examples/tree/master/contexa-example-quickstart',
    );
    expect(screen.getByRole('link', { name: word('adopt.repository') })).toHaveAttribute(
      'href',
      'https://github.com/contexa-security/contexa',
    );
    expect(screen.getByRole('link', { name: word('adopt.legacyExample') })).toHaveAttribute(
      'href',
      'https://github.com/contexa73/contexa-examples/tree/master/contexa-example-legacy-system',
    );
    expect(screen.getByText(word('space.r7.adopt.legacy.body'))).toBeInTheDocument();
    expect(presses(container)).toBe(3);
    const actions = zone(container, 'actions');
    expect(within(actions).getByRole('link', { name: word('frame.back') })).toHaveAttribute('href', '/adopt');
    expect(within(actions).getByRole('link', { name: word('space.r7.adopt.attach.next') })).toHaveAttribute(
      'href',
      '/adopt?step=on',
    );
  });
});

describe('adopting Contexa: turning it on', () => {
  it.each([
    {
      name: 'this demo',
      stats: stats(
        760,
        { ALLOW: 728, CHALLENGE: 1, BLOCK: 31, ESCALATE: 0 },
        '2026-10-04T06:00:00Z',
        '2026-10-18T09:33:47Z',
      ),
      counts: { count: '760', block: '31', challenge: '1', review: '0' },
      period: { from: '2026-10-04', to: '2026-10-18' },
      mode: 'ENFORCE',
    },
    {
      name: 'another record',
      stats: stats(
        6341,
        { ALLOW: 3856, CHALLENGE: 1786, BLOCK: 0, ESCALATE: 699 },
        '2026-10-01T00:00:00Z',
        '2026-10-02T23:59:59Z',
      ),
      counts: { count: '6,341', block: '0', challenge: '1,786', review: '699' },
      period: { from: '2026-10-01', to: '2026-10-02' },
      mode: 'SHADOW',
    },
  ])('counts what record-only mode would have kept from the judgments ($name)', async (record) => {
    answers = {
      '/api/stats': ok(record.stats),
      '/api/settings': ok(settings({ behaviorDays: 400, promptOriginalDays: 90 }, null, record.mode)),
    };
    const { container } = open('/adopt?step=on');
    expect(await screen.findByText(fill('space.r7.adopt.watch.counts', record.counts))).toBeInTheDocument();
    expect(zone(container, 'source')).toHaveTextContent(fill('space.r7.adopt.on.source', record.period));
    expect(await screen.findByText(word(`space.r7.adopt.on.mode.${record.mode}`))).toBeInTheDocument();
    expect(screen.getByLabelText(word('space.r7.adopt.watch.code'))).toHaveTextContent('mode: SHADOW');
    expect(screen.getByText('mode: ENFORCE')).toHaveAttribute('data-original');
    expect(presses(container)).toBe(0);
    const docs = within(zone(container, 'actions')).getByRole('link', { name: word('space.r7.adopt.docs') });
    expect(docs).toHaveAttribute('href', 'https://docs.ctxa.ai');
    expect(docs).toHaveAttribute('target', '_blank');
  });

  it('leaves the counts and their source out while the demo has no judgment', async () => {
    answers = { '/api/stats': ok(stats(0, { ALLOW: 0, CHALLENGE: 0, BLOCK: 0, ESCALATE: 0 }, '-', '-')) };
    const { container } = open('/adopt?step=on');
    expect(await screen.findByText(word('space.r7.adopt.watch.body'))).toBeInTheDocument();
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
    expect(container.textContent).not.toContain(word('space.r7.adopt.watch.counts').split('{{')[0] ?? '');
  });
});
