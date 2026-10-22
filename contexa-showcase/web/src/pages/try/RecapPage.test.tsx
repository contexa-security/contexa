import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PromptQualityView } from '../../api/promptQuality';
import type { PublicSettingsView } from '../../api/settings';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import RecapPage from './RecapPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

function rate(hits: number, total: number) {
  return { hits, total, rate: hits / total, low: 0.9, high: 0.99, preliminary: false };
}

/** A published batch as the portal's prompt-quality view gives it (the numbers are this test's own). */
const PUBLISHED = {
  measuredAt: '2026-10-16T05:40:00Z',
  setting: 'a'.repeat(64),
  batch: 'batch-p7-1',
  protocol: 'protocol-p7-1',
  delivery: rate(10, 11),
  reaction: { direction: rate(99, 122), minimumKept: rate(40, 40), consistency: rate(110, 122) },
  invariance: { firstStepFacts: rate(26, 26), decisions: rate(37, 39), decisionChanges: 2 },
  injection: { changed: 1, unchanged: rate(3, 4) },
  accuracy: rate(950, 960),
  consistency: rate(37, 39),
  reasonMatch: rate(1234, 1250),
} as unknown as PromptQualityView;

/** The running settings as the portal's /api/settings gives them (the values are this test's own). */
const SETTINGS: PublicSettingsView = {
  waf: { image: null, ruleSet: null },
  permission: { roleRules: [] },
  threshold: { nightStart: null, nightEnd: null, volumeLimit: null, dormantWindowDays: null },
  businessRecord: {
    exportPolicyKey: null,
    assignedExportLimit: null,
    ticketAndOncallExempt: null,
    historyWindowDays: null,
    exportHistoryWindowDays: null,
    accessPolicies: [],
  },
  engine: { chatModel: null, effectiveMode: null, inspectorConditions: 17 },
  retention: { behaviorDays: 90, promptOriginalDays: 30 },
  ruleVersion: null,
};

function teaser(key: string, values: Readonly<Record<string, unknown>>, holds: boolean | null = null) {
  return { key, values, holds, source: null, missing: null };
}

/** The teaser records as the portal's /api/teasers gives them (TeaserService); the values are this test's own. */
function teasers(resume: boolean) {
  return {
    computedAt: '2026-10-18T00:00:00Z',
    teasers: [
      teaser('FOLLOW_LEARNED', { learned: 31 }),
      teaser('E1_RESULT_FACTS', { departures: 6 }, true),
      teaser('LEARN_AFTER_FALSE_BLOCKS', { contexa: 1, numberRule: 44, normalRuns: 70 }, true),
      teaser('G_RULES_RESUME', { reissueMs: resume ? 2400 : null }, resume),
      teaser('CHALLENGE_OUTCOMES', { resumed: 1500 }),
    ],
  };
}

const SEEN_AT = [
  '/try/attacker/run',
  '/try/attacker/compare',
  '/try/owner/result',
  '/try/attacker/reason',
  '/try/attacker/after',
  '/try/stack',
];

let seen: readonly number[];
let teaserAnswer: unknown;
/** Try 3's learned requests at its start and end, as the part's wrap-up gives them (act-end 3); per test. */
let learning: { readonly from: number; readonly to: number } | null;
let quality: { readonly status: number; readonly body: unknown };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  seen = [1, 2, 3, 4, 5, 6];
  teaserAnswer = teasers(true);
  learning = { from: 12, to: 16 };
  quality = { status: 200, body: PUBLISHED };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, { readonly status: number; readonly body: unknown }> = {
        '/api/benchmark': { status: 200, body: { engine: { decisions: 2468 }, controls: [], suites: [] } },
        '/api/benchmark/prompt-quality': quality,
        '/api/teasers': { status: 200, body: teaserAnswer },
        '/api/journey/act-end?act=3': {
          status: 200,
          body: learning
            ? { act: 3, caseKey: 'A6T', source: 'MEASUREMENT', runId: 'run-a6t', values: { ...learning, requests: 5 } }
            : { act: 3, caseKey: 'A6T', source: 'NONE', runId: null, values: {} },
        },
        '/api/settings': { status: 200, body: SETTINGS },
        '/api/visitor': { status: 200, body: { predictions: {} } },
        '/api/journey': {
          status: 200,
          body: {
            state: { route: 'DEFAULT', act: 5, step: 'recap', differences: seen },
            runs: [],
            predictions: [],
          },
        },
      };
      const { status, body } = bodies[url] ?? { status: 404, body: null };
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/try/summary/recap']}>
        <RecapPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function cards(): readonly HTMLElement[] {
  const list = screen.getByRole('list', { name: word('difference.cards.title') });
  return within(list).getAllByRole('link');
}

function card(difference: number): HTMLElement {
  return required(cards()[difference - 1], `card ${difference}`);
}

/** Screen 5-2 (화면재편-기획안 7절, T8): six difference cards with their measured line, each a way back. */
// The final screen design (최종화면-구현계획 F0-1) opens this screen at no address any more; its address leads to the
// new flow. The screen and this test are on the deletion list for the user (최종화면-구현계획 4절).
describe.skip('the six differences', () => {
  it('draws one card per difference leading to the screen where it is seen, and the identity line', async () => {
    const { container } = open();
    await within(card(6)).findByText(fill('p5.recap.measure.6', { from: '12', to: '16' }));
    expect(cards().map((link) => link.getAttribute('href'))).toEqual(SEEN_AT);
    for (const difference of [1, 2, 3, 4, 5, 6]) {
      expect(card(difference)).toHaveTextContent(word(`difference.${difference}`));
      expect(card(difference)).toHaveTextContent(word('difference.back'));
    }
    expect(screen.getByText(word('identity.line'))).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.5-2.title'));
    expect(screen.getByRole('link', { name: word('screen.5-2.next') })).toHaveAttribute(
      'href',
      '/try/summary/adopt',
    );
    // The cards are the screen's action (counted apart); the run table and the old chips are gone.
    expect(container.querySelector('table')).toBeNull();
    expect(required(container.querySelector('[data-count="exempt"]'), 'the cards')).toContainElement(card(1));
    const text = document.body.textContent ?? '';
    for (const key of [
      'recap.title',
      'recap.caption',
      'recap.lab.try',
      'value.title',
      'value.limits',
      'recap.next',
    ]) {
      expect(text, key).not.toContain(word(key));
    }
  });

  it("writes each card's measured line from the server's values", async () => {
    open();
    await within(card(6)).findByText(fill('p5.recap.measure.6', { from: '12', to: '16' }));
    expect(card(1)).toHaveTextContent(fill('p5.recap.measure.1', { decisions: '2,468' }));
    expect(card(2)).toHaveTextContent(fill('p5.recap.measure.2', { learned: '31', departures: '6' }));
    expect(card(3)).toHaveTextContent(
      fill('p5.recap.measure.3', { contexa: '1', numberRule: '44', normal: '70' }),
    );
    expect(
      await within(card(4)).findByText(fill('p5.recap.measure.4.quality', { hits: '1,234', total: '1,250' })),
    ).toBeInTheDocument();
    expect(card(5)).toHaveTextContent(fill('p5.recap.measure.5', { seconds: '2.4', resumed: '1,500' }));
    const source = required(document.querySelector<HTMLElement>('[data-zone="source"]'), 'the source line');
    expect(source).toHaveTextContent(word('frame.source.measured'));
  });

  it('takes the other words where the record does not make the sentence true', async () => {
    teaserAnswer = teasers(false);
    learning = { from: 12, to: 12 };
    open();
    expect(
      await within(card(6)).findByText(fill('p5.recap.measure.6.flat', { from: '12', to: '12' })),
    ).toBeInTheDocument();
    expect(card(5)).toHaveTextContent(fill('p5.recap.measure.5.fallback', { resumed: '1,500' }));
    expect(card(6)).not.toHaveTextContent(fill('p5.recap.measure.6', { from: '12', to: '12' }));
  });

  it('states the conditions checked in every answer while no reasons batch is published (404)', async () => {
    quality = { status: 404, body: null };
    open();
    expect(await within(card(4)).findByText(fill('p5.recap.measure.4', { n: '17' }))).toBeInTheDocument();
    expect(card(4)).not.toHaveTextContent(
      fill('p5.recap.measure.4.quality', { hits: '1,234', total: '1,250' }),
    );
  });

  it('says a value has no record yet instead of a blank or a made-up number', async () => {
    teaserAnswer = { computedAt: '2026-10-18T00:00:00Z', teasers: [] };
    learning = null;
    open();
    await within(card(1)).findByText(fill('p5.recap.measure.1', { decisions: '2,468' }));
    for (const difference of [2, 3, 5, 6]) {
      expect(card(difference)).toHaveTextContent(word('p5.recap.measure.none'));
    }
  });

  it('keeps the question of a difference not seen yet, says so, and leads to the screen that shows it', async () => {
    seen = [1, 2];
    open();
    await within(card(1)).findByText(fill('p5.recap.measure.1', { decisions: '2,468' }));
    expect(card(3)).toHaveTextContent(word('difference.question.3'));
    expect(card(3)).toHaveTextContent(word('p5.recap.unseen'));
    expect(card(3)).toHaveTextContent(word('p5.recap.go'));
    expect(card(3)).not.toHaveTextContent(
      fill('p5.recap.measure.3', { contexa: '1', numberRule: '44', normal: '70' }),
    );
    expect(card(3)).toHaveAttribute('href', '/try/owner/result');
  });
});
