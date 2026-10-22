import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BenchmarkView } from '../../api/benchmark';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { BlindSpotProof } from './BlindSpotProof';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string, values: Readonly<Record<string, string | number>> = {}): string {
  return Object.entries(values).reduce(
    (text, [name, value]) => text.replace(`{{${name}}}`, String(value)),
    KO[key] ?? key,
  );
}

/** A benchmark as the portal sends it, with only what the proof reads. */
const VIEW = {
  spec: { settingHash: 'setting-1' },
  cases: [
    { key: 'S13', title: { ko: 'S13', en: 'S13' } },
    { key: 'S13T', title: { ko: 'S13T', en: 'S13T' } },
  ],
  engine: { agreement: { decisions: 12, modelAnswered: 9, asAnswered: 9, technical: 0, held: 3 } },
  blindSpot: {
    attacks: [{ key: 'S13', runs: 5, allPassed: 5, contexa: { STOPPED: 4, MISSED: 1 } }],
    normals: [{ key: 'S13T', runs: 5, allPassed: 5, contexa: { PASSED: 5 } }],
  },
} as unknown as BenchmarkView;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () => new Response(JSON.stringify({ reasonMatch: { hits: 40, total: 42 } }), { status: 200 }),
    ),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(view: BenchmarkView) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <BlindSpotProof view={view} />
    </QueryClientProvider>,
  );
}

/** 4.8 of the v21 plan: the blind-spot proof states the portal's counts as they came, misses included. */
describe('the blind-spot proof of the benchmark', () => {
  it('states the runs all four existing controls let through and what Contexa did in them, misses included', async () => {
    open(VIEW);
    const attacks = screen.getByRole('region', { name: word('bench.r7.proof.attacks') });
    const row = within(attacks).getByRole('row', { name: new RegExp(word('bench.r7.caseName.S13')) });
    expect(row).toHaveTextContent('5/5');
    expect(row).toHaveTextContent(
      word('bench.r7.proof.result', { word: KO['main.result.STOPPED'] ?? '', n: 4 }),
    );
    expect(row).toHaveTextContent(
      word('bench.r7.proof.result', { word: KO['main.result.MISSED'] ?? '', n: 1 }),
    );
    const normals = screen.getByRole('region', { name: word('bench.r7.proof.normals') });
    expect(
      within(normals).getByRole('row', { name: new RegExp(word('bench.r7.caseName.S13T')) }),
    ).toHaveTextContent(word('bench.r7.proof.result', { word: KO['main.result.PASSED'] ?? '', n: 5 }));
    expect(
      screen.getByText(word('bench.r7.proof.agreement', { as: 9, answered: 9, technical: 0, held: 3 })),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(word('bench.r7.proof.reasons', { hits: 40, total: 42 })),
    ).toBeInTheDocument();
  });

  it('says when no attack run was let through by all four, and draws nothing from an older portal', () => {
    const none = { ...VIEW, blindSpot: { attacks: [], normals: [] } } as unknown as BenchmarkView;
    const { unmount } = open(none);
    expect(screen.getByText(word('bench.r7.proof.noAttacks'))).toBeInTheDocument();
    unmount();
    const { container } = open({ ...VIEW, blindSpot: undefined } as unknown as BenchmarkView);
    expect(container).toBeEmptyDOMElement();
  });
});
