import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PromptQualityView } from '../../api/promptQuality';
import type { PublicSettingsView } from '../../api/settings';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import ValuePage from './ValuePage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

function rate(hits: number, total: number) {
  return { hits, total, rate: hits / total, low: 0.9, high: 0.99, preliminary: false };
}

/** A published batch as the portal's prompt-quality view gives it (the numbers are this test's own). */
const published: PromptQualityView = {
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
};

/** The running settings as the portal's /api/settings gives them (the values are this test's own). */
const settings: PublicSettingsView = {
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

let quality: { readonly status: number; readonly body: unknown };

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const { status, body } = url.startsWith('/api/benchmark/prompt-quality')
        ? quality
        : url === '/api/settings'
          ? { status: 200, body: settings }
          : { status: 404, body: null };
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function reasonsCard(): HTMLElement {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/try/summary/value']}>
        <Routes>
          <Route path="*" element={<ValuePage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  // The six cards in the order of the six differences; the fourth leaves the reasons.
  const cards = within(screen.getByRole('list', { name: word('value.title') })).getAllByRole('listitem');
  expect(cards).toHaveLength(6);
  const card = required(cards[3], 'card 4');
  expect(card).toHaveTextContent(word('value.name.4'));
  return card;
}

/** U7-1: the measured line of the "leaves the reasons" card, a server value. */
describe('core value: the reasons card', () => {
  it('states the published reasons matching their facts and the sealed inputs', async () => {
    quality = { status: 200, body: published };
    const card = reasonsCard();
    expect(
      await within(card).findByText(fill('value.measure.4.quality', { hits: '1,234', total: '1,250' })),
    ).toBeInTheDocument();
    expect(within(card).queryByText(fill('value.measure.4', { n: '17' }))).not.toBeInTheDocument();
  });

  it('states the conditions checked in every answer while nothing is published (404)', async () => {
    quality = { status: 404, body: null };
    const card = reasonsCard();
    expect(await within(card).findByText(fill('value.measure.4', { n: '17' }))).toBeInTheDocument();
    expect(
      within(card).queryByText(fill('value.measure.4.quality', { hits: '1,234', total: '1,250' })),
    ).not.toBeInTheDocument();
  });
});
