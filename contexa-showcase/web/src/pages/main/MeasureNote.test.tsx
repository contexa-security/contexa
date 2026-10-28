import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { MeasureNote } from './MeasureNote';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

const CASE = {
  key: 'T5',
  version: 1,
  title: { ko: '위임 만료 뒤의 예약 실행', en: 'A scheduled run after the delegation expired' },
  protagonist: 'eng-k',
  agentName: 'report',
  agentTitle: { ko: '보고서 에이전트', en: 'Report agent' },
  sender: 'DELEGATED_AGENT',
  instruction: { ko: '지시', en: 'Instruction' },
  delegation: null,
  classification: 'THREAT',
  normalPair: 'N1',
  recorded: { runId: 'run-t5', startedAt: '2026-10-24T04:46:33Z', runs: 18, sameAsLatest: 17 },
  normalRecorded: null,
};

let body: unknown;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  body = CASE;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function note(own: boolean, stopReason: string | null = null) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <MeasureNote own={own} stopReason={stopReason} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('what the agent screens numbers stand on (AS-5)', () => {
  it("says whose run the screen shows, and the recordings' counts exactly as the portal counted them", async () => {
    note(false);

    expect(screen.getByText(word('main.agent.measure.recorded'))).toBeInTheDocument();
    expect(
      await screen.findByText(
        word('main.agent.measure.stats').replace('{{runs}}', '18').replace('{{same}}', '17'),
      ),
    ).toBeInTheDocument();
  });

  it("says the screen shows the visitor's own run when it does", () => {
    note(true);

    expect(screen.getByText(word('main.agent.measure.own'))).toBeInTheDocument();
    expect(screen.queryByText(word('main.agent.measure.recorded'))).not.toBeInTheDocument();
  });

  it('always says the limit: the judgment can differ from run to run and one case is not all work', () => {
    note(false);

    expect(screen.getByText(word('main.agent.measure.limit'))).toBeInTheDocument();
  });

  it('shows no count when the case has no recording, never a made up one', async () => {
    body = { ...CASE, recorded: null };
    note(false);

    expect(screen.getByText(word('main.agent.measure.limit'))).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByText(/회 기록했고/)).not.toBeInTheDocument();
  });

  it.each([
    ['CAP_TOOL_CALLS', 'main.agent.cap.CAP_TOOL_CALLS'],
    ['CAP_DECISIONS', 'main.agent.cap.CAP_DECISIONS'],
    ['CAP_INPUT_TOKENS', 'main.agent.cap.CAP_INPUT_TOKENS'],
  ])('closes a run a live limit stopped (%s) as "so far", in its own words (AC-3)', (reason, key) => {
    note(true, reason);

    expect(screen.getByText(word(key))).toBeInTheDocument();
    expect(screen.getByText(word('main.agent.cap.so_far'))).toBeInTheDocument();
  });

  it('says nothing of a limit when the run ended on its own', () => {
    note(true, 'ANSWERED');

    expect(screen.queryByText(word('main.agent.cap.so_far'))).not.toBeInTheDocument();
    note(true, 'TOOL_BUDGET');
    expect(screen.queryByText(word('main.agent.cap.so_far'))).not.toBeInTheDocument();
  });

  // 구현계획 AC-N2: the first line says whose run it is; the counts and the limit wait under that line.
  it('says whose run it is in view and keeps the counts and the limit under that line', async () => {
    const { container } = note(false);
    const fold = container.querySelector('details[data-fold="measure-note"]') as HTMLDetailsElement | null;
    expect(fold).not.toBeNull();
    expect(fold?.open).toBe(false);
    expect(fold?.querySelector('summary')).toHaveTextContent(word('main.agent.measure.recorded'));
    expect(fold?.contains(screen.getByText(word('main.agent.measure.limit')))).toBe(true);
  });

  it('keeps a live limit in view, outside the fold', () => {
    const { container } = note(true, 'CAP_TOOL_CALLS');
    const fold = container.querySelector('details[data-fold="measure-note"]');
    expect(fold?.contains(screen.getByText(word('main.agent.cap.so_far')))).toBe(false);
  });

  it('is a labelled aside so a screen reader can find it', () => {
    note(true);

    expect(screen.getByRole('complementary', { name: word('main.agent.measure.label') })).toBeInTheDocument();
  });
});
