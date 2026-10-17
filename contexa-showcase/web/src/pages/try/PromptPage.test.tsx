import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { OtherBundleView } from '../../api/promptQuality';
import type { TeasersView } from '../../api/teasers';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import PromptPage from './PromptPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string | number>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values[name] ?? ''));
}

/** The measured run the teasers name: the page's run when the visitor has none of their own. */
const teasers: TeasersView = {
  computedAt: '2026-10-16T05:40:00Z',
  teasers: [
    { key: 'G_HOW_LINES', values: {}, holds: null, source: { kind: 'RUN', ref: 'run-a3' }, missing: null },
  ],
};

/** One side of the comparison as the portal's other-bundle view gives it (the values are this test's own). */
function side(runId: string, version: string, userPromptLines: number) {
  return {
    runId,
    stepNo: 1,
    bundle: { version, hash: 'abcdef0123456789', selectionSource: 'REGISTRY' },
    userPrompt: '=== REQUEST ===',
    systemPromptLines: 106,
    userPromptLines,
  };
}

const compared: OtherBundleView = {
  available: true,
  reason: null,
  current: side('run-a3', '2026.10.16-v20.23', 52),
  other: side('run-v19', '2026.10.11-v19.19', 252),
  lines: { before: 'v19', beforeLines: 252, after: 'v20', afterLines: 52 },
};

let other: OtherBundleView;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body: unknown =
        url === '/api/teasers' ? teasers : url === '/api/runs/run-a3/steps/1/other-bundle' ? other : null;
      return new Response(body === null ? null : JSON.stringify(body), { status: body === null ? 404 : 200 });
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
      <MemoryRouter initialEntries={['/try/prompt']}>
        <Routes>
          <Route path="*" element={<PromptPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** U2-6: the same case's user prompt length under the earlier and the later bundle, a server line. */
describe('prompt page: the same case under both bundles', () => {
  it("states both user prompts' lines, the earlier bundle first, beside the comparison", async () => {
    other = compared;
    open();
    expect(await screen.findByRole('button', { name: word('prompt.compare.open') })).toBeInTheDocument();
    const line = await screen.findByText(
      fill('prompt.compare.lines', { before: 'v19', beforeLines: '252', after: 'v20', afterLines: '52' }),
    );
    expect(line).toHaveAttribute('data-lines');
  });

  it('states no such line while the server gives no ordered pair', async () => {
    other = { ...compared, lines: null };
    const { container } = open();
    expect(await screen.findByRole('button', { name: word('prompt.compare.open') })).toBeInTheDocument();
    expect(container.querySelector('[data-lines]')).toBeNull();
  });
});
