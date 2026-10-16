import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PublicSettingsView } from '../../api/settings';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import AdoptChangePage from './AdoptChangePage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

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

let answer: unknown;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url === '/api/settings'
        ? new Response(JSON.stringify(answer), { status: 200 })
        : new Response(null, { status: 404 }),
    ),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/try/summary/adopt']}>
        <Routes>
          <Route path="*" element={<AdoptChangePage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** U-7: the "data kept" cell names the sealed inputs' retention and the inspected share the settings state. */
describe('adopt screen sealed inputs', () => {
  it('names the retention days and the inspected share when the settings state them', async () => {
    answer = { ...settings, sealedEvidence: { samplePercent: 100, cleanPeriodDays: 90 } };
    open();
    // The settings have arrived once the retention the same cell states is shown.
    await screen.findByText(fill('adoptChange.value.data', { behavior: '90', prompt: '30' }));
    expect(screen.getByText(fill('adoptChange.value.sealKept', { days: '90', percent: '100' }))).toBeInTheDocument();
    expect(screen.queryByText(word('adoptChange.value.seal'))).not.toBeInTheDocument();
  });

  it('says what the library does without a number when the settings do not state them', async () => {
    for (const sealedEvidence of [undefined, null, { samplePercent: null, cleanPeriodDays: 90 }]) {
      answer = sealedEvidence === undefined ? settings : { ...settings, sealedEvidence };
      const { unmount } = open();
      await screen.findByText(fill('adoptChange.value.data', { behavior: '90', prompt: '30' }));
      expect(screen.getByText(word('adoptChange.value.seal'))).toBeInTheDocument();
      expect(
        screen.queryByText(fill('adoptChange.value.sealKept', { days: '90', percent: '100' })),
      ).not.toBeInTheDocument();
      unmount();
    }
  });
});
