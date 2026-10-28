import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import RequestPage from './RequestPage';

/** The case list with the stolen account's case S13 and its employee, as the portal lists them. */
const OPTIONS = {
  employees: [
    {
      key: 'eng-k',
      role: 'ENGINEER',
      displayName: 'Design engineer K',
      department: 'Design engineering HX',
      officeNetwork: '10.40.21.0/24',
      assignedProjects: ['HX-310'],
      customersManaged: 0,
      roleAllows: {},
    },
  ],
  projects: [],
  timeSlots: [],
  items: [],
  operations: [],
  calls: [],
  assessmentReasons: [],
  cases: [
    {
      key: 'S13',
      version: 1,
      title: { ko: '담당 범위 안에서 평소의 20배 넘게 반출', en: 'An export over 20 times the usual size' },
      classification: 'THREAT',
      steps: 1,
      conditions: {
        employee: 'eng-k',
        timeSlot: 'AFTERNOON',
        place: 'OFFICE',
        device: 'NEW',
        operation: 'EXPORT',
        target: 'ASSIGNED',
        items: 480,
        approval: false,
        ticket: 'NONE',
        claim: 'NONE',
        onCall: false,
      },
      facts: [],
      requests: [
        {
          operation: 'EXPORT',
          project: 'HX-310',
          document: null,
          target: 'ASSIGNED',
          customer: null,
          items: 480,
          claimedTicket: null,
          visitorSends: false,
        },
      ],
    },
    {
      key: 'S16',
      version: 1,
      title: { ko: '권한 안의 문서 반출', en: 'Documents within the rights' },
      classification: 'THREAT',
      steps: 3,
      conditions: {
        employee: 'eng-k',
        timeSlot: 'AFTERNOON',
        place: 'OFFICE',
        device: 'USUAL',
        operation: 'DOWNLOAD',
        target: 'ASSIGNED',
        items: null,
        approval: false,
        ticket: 'NONE',
        claim: 'NONE',
        onCall: false,
      },
      facts: [
        {
          kind: 'DOCUMENT',
          document: { title: { ko: '고객사 공급 단가 산정표', en: 'Supply price sheet' } },
        },
        {
          kind: 'DOCUMENT',
          document: { title: { ko: '경쟁 입찰 대응 전략 메모', en: 'Bid strategy memo' } },
        },
      ],
      requests: [
        {
          operation: 'DOWNLOAD',
          project: 'HX-310',
          document: { project: 'HX-310' },
          target: 'ASSIGNED',
          customer: null,
          items: null,
          claimedTicket: null,
          visitorSends: true,
        },
      ],
    },
  ],
};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const bodies: Record<string, unknown> = {
        '/api/visitor': { predictions: {} },
        '/api/lab/options': OPTIONS,
        '/guides/guides.json': {
          request: {
            file: 'console.webm',
            captions: { ko: 'console.ko.vtt', en: 'console.en.vtt' },
            durationSec: 74,
            recordedAt: '2026-10-21T03:30:00Z',
            screens: 'v4',
          },
        },
      };
      const body = bodies[url];
      return new Response(body === undefined ? null : JSON.stringify(body), { status: body ? 200 : 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function open(role: 'attacker' | 'insider' = 'attacker') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[role === 'insider' ? '/insider/request' : '/attack/request']}>
        <Routes>
          <Route path="*" element={<RequestPage role={role} />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Review before the guide videos (2026-10-21): the request screens of 2-1, 4-1 and 5-1.
describe('the request before it is sent', () => {
  it('says the send waits for the prediction, and stops saying so once one is picked (B-09)', async () => {
    open();
    expect(await screen.findByText(i18n.t('main.request.pickFirst'))).toBeInTheDocument();
    fireEvent.click(screen.getByText(i18n.t('main.request.call.BLOCK')));
    expect(screen.queryByText(i18n.t('main.request.pickFirst'))).toBeNull();
  });

  it('names the stolen account as the account, not the person (V-56)', async () => {
    open();
    const name = i18n.t('person.eng-k', { defaultValue: 'Design engineer K' });
    expect(await screen.findByText(i18n.t('main.request.account.attacker', { name }))).toHaveTextContent(
      `${name}의 계정`,
    );
  });

  it('keeps the case number out of the heading (V-48)', async () => {
    open();
    const heading = await screen.findByRole('heading', { name: /요청 정보/ });
    expect(heading.textContent).not.toContain('S13');
  });

  // 가이드영상-제작기획안.md 3.3절: the request guide stands on the request screens of all three lanes, in the title zone.
  it('offers the request guide in the title zone, before the first send', async () => {
    open();
    const button = await screen.findByRole('button', { name: '미리보기 영상 · 1분 14초' });
    expect(button.closest('[data-zone="title"]')).not.toBeNull();
  });

  // 구현계획 AC-N2: the intro says the situation, so the rows of the request wait under one line, all of them; only the
  // insider's documents, which the call is made on, stay in view.
  it('keeps every row of the request under one line, and tells the situation in the intro', async () => {
    const { container } = open();
    const fold = await waitFor(() => {
      const found = container.querySelector('details[data-fold="request"]');
      expect(found).not.toBeNull();
      return found as HTMLDetailsElement;
    });
    expect(fold.open).toBe(false);
    expect(within(fold).getByText(i18n.t('main.request.fold'))).toBeInTheDocument();
    const outside = Array.from(container.querySelectorAll('dl')).filter((list) => !fold.contains(list));
    expect(outside).toHaveLength(0);
    const inside = Array.from(fold.querySelectorAll('dt')).map((term: HTMLElement) => term.textContent);
    expect(inside).toEqual([
      i18n.t('main.request.row.account'),
      i18n.t('main.request.row.time'),
      i18n.t('main.request.row.place'),
      i18n.t('main.request.row.auth'),
      i18n.t('main.request.row.what'),
      i18n.t('main.request.row.records'),
    ]);
  });

  it('says in the fold that the rows are the case as defined', async () => {
    const { container } = open();
    const fold = await waitFor(() => {
      const found = container.querySelector('details[data-fold="request"]');
      expect(found).not.toBeNull();
      return found as HTMLDetailsElement;
    });
    expect(fold.textContent).toContain(i18n.t('main.request.asDefined'));
  });

  it('stands the fold and the call in one column when nothing else of the request is in view', async () => {
    const { container } = open();
    await waitFor(() => expect(container.querySelector('[data-fold-only]')).not.toBeNull());
    const insider = open('insider');
    await waitFor(() =>
      expect(insider.container.querySelector('details[data-fold="request"]')).not.toBeNull(),
    );
    expect(insider.container.querySelector('[data-fold-only]')).toBeNull();
  });

  it("keeps the insider's documents in view, since the call is made on their titles", async () => {
    const { container } = open('insider');
    const fold = await waitFor(() => {
      const found = container.querySelector('details[data-fold="request"]');
      expect(found).not.toBeNull();
      return found as HTMLDetailsElement;
    });
    const outside = Array.from(container.querySelectorAll('dl')).filter((list) => !fold.contains(list));
    const names = outside.flatMap((list) =>
      Array.from(list.querySelectorAll('dt')).map((term: HTMLElement) => term.textContent),
    );
    expect(names).toEqual([i18n.t('main.request.row.what')]);
    expect(within(outside[0] as HTMLElement).getByText(/고객사 공급 단가 산정표/)).toBeInTheDocument();
  });

  // 구현계획 AC-N2: a screen says what it is and asks one thing; the first view stays within 200 characters.
  it('stays within 200 characters at first sight, what a closed fold holds not counted', async () => {
    const { container } = open();
    await screen.findByText(i18n.t('main.request.call.BLOCK'));
    const main = container.querySelector('main')?.cloneNode(true) as HTMLElement;
    main.querySelectorAll('details:not([open]) > :not(summary)').forEach((hidden) => hidden.remove());
    expect((main.textContent ?? '').replace(/\s/g, '').length).toBeLessThanOrEqual(200);
  });

  it('has no side note under the two calls: the intro says there is a call to make', async () => {
    open();
    await screen.findByText(i18n.t('main.request.call.BLOCK'));
    expect(screen.queryByText(i18n.t('main.request.noAnswer'))).toBeNull();
  });

  it('counts an extra check as a call that the data stays in (V-37)', async () => {
    open();
    expect(await screen.findByText(i18n.t('main.request.call.BLOCK.hint'))).toHaveTextContent('추가 인증');
  });
});
