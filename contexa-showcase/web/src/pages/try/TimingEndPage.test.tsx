import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { portalStub } from '../../test/timingFixture';
import TimingEndPage from './TimingEndPage';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

function fill(key: string, values: Readonly<Record<string, string>>): string {
  return word(key).replace(/\{\{(\w+)\}\}/g, (_, name: string) => values[name] ?? '');
}

let actEnd: unknown = null;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal('fetch', vi.fn(portalStub(() => ({ '/api/journey/act-end?act=4': actEnd }))));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/try/timing/end']}>
        <TimingEndPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function card(source: string, values: Record<string, unknown>) {
  return { act: 4, caseKey: 'A3A', source, runId: 'run-0a3a00000001', values };
}

const SENT = {
  requested: 4831,
  engineAction: 'ESCALATE',
  applied: 'NEXT_REQUEST',
  analysisMs: 4199,
  delivered: 4831,
  nextStopped: true,
};

/** Screen 4-4, the part's wrap-up (화면재편 T8): one sentence from the record of the request sent on 4-1. */
// The final screen design (최종화면-구현계획 F0-1) opens this screen at no address any more; its address leads to the
// new flow. The screen and this test are on the deletion list for the user (최종화면-구현계획 4절).
describe.skip('part 4 wrap-up', () => {
  it("states what the visitor's own request did, with the run's source line and the next part's question", async () => {
    actEnd = card('VISITOR_RUN', SENT);
    const { container } = open();
    expect(await screen.findByText(fill('actEnd.4.next.stopped', { delivered: '4,831' }))).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word('screen.4-4.title'));
    expect(screen.getByText(word('screen.4-4.guide'))).toBeInTheDocument();
    expect(required(container.querySelector('[data-zone="source"]'), 'the source line')).toHaveTextContent(
      word('frame.source.run'),
    );
    expect(screen.getByRole('link', { name: word('screen.4-4.next') })).toHaveAttribute('href', '/part/5');
  });

  it('says the sentence comes from the measurement when the visitor did not send it', async () => {
    actEnd = card('MEASUREMENT', { ...SENT, delivered: 1200, nextStopped: false });
    const { container } = open();
    expect(await screen.findByText(fill('actEnd.4.next.passed', { delivered: '1,200' }))).toBeInTheDocument();
    expect(required(container.querySelector('[data-zone="source"]'), 'the source line')).toHaveTextContent(
      word('frame.source.measured'),
    );
  });

  it('shows no sentence and no source line when there is no run at all', async () => {
    actEnd = { act: 4, caseKey: 'A3A', source: 'NONE', runId: null, values: {} };
    const { container } = open();
    expect(await screen.findByText(word('screen.4-4.guide'))).toBeInTheDocument();
    for (const key of ['actEnd.4.next.stopped', 'actEnd.4.next.passed', 'actEnd.4.next.only', 'actEnd.4.before', 'actEnd.4.other']) {
      expect(document.body.textContent ?? '').not.toContain(word(key).split('{{')[0] ?? '');
    }
    expect(container.querySelector('[data-zone="source"]')).toBeNull();
  });
});
