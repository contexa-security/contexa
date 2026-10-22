import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
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
          console: {
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

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/attack/request']}>
        <Routes>
          <Route path="*" element={<RequestPage role="attacker" />} />
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

  it('offers the console guide beside the headline, before the first send (가이드영상-계획.md 3절)', async () => {
    open();
    const button = await screen.findByRole('button', { name: '미리 보기 · 1분 14초' });
    expect(button.closest('[data-zone="title"]')).not.toBeNull();
  });

  it('counts an extra check as a call that the data stays in (V-37)', async () => {
    open();
    expect(await screen.findByText(i18n.t('main.request.call.BLOCK.hint'))).toHaveTextContent('추가 인증');
  });
});
