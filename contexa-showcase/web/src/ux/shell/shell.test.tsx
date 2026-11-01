import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import { THEME_STORAGE_KEY } from '../theme';
import { UxApp } from '../UxApp';
import { DRAWER_QUERY, RAIL_QUERY } from '../useMedia';

const STATS = {
  computedAt: '2026-10-31T15:59:45Z',
  runs: { completed: 6872, failed: 87, today: 8, live: 2046, firstAt: null, lastAt: null },
  decisionTime: { decisions: 13733, p50Ms: 5959, p95Ms: 16321 },
  engineActions: { ALLOW: 9932, CHALLENGE: 2148, BLOCK: 517, ESCALATE: 1136 },
  engineDecisions: 13733,
};
const LIVE = { scenarios: [], turnstileSiteKey: null, dailyRuns: 10, remainingToday: 10, paused: false };

function Where() {
  const location = useLocation();
  return <output data-testid="where">{location.pathname}</output>;
}

function open(address: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[address]}>
        <UxApp />
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function stubMedia(narrow: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: narrow && query === DRAWER_QUERY,
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  }));
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  stubMedia(false);
  vi.stubGlobal('fetch', (input: RequestInfo | URL) => {
    const path = String(input);
    const body = path === '/api/stats' ? STATS : path === '/api/live/config' ? LIVE : null;
    return Promise.resolve(
      body
        ? new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
        : new Response('{}', { status: 404 }),
    );
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
});

describe('the top bar', () => {
  it('shows whether live decisions run and the portal counts', async () => {
    open('/');
    expect(await screen.findByText('실시간 판정 가동')).toBeInTheDocument();
    const counts = await screen.findByText(/오늘 방문자 실행/);
    expect(counts).toHaveTextContent('오늘 방문자 실행 8 · 누적 판정 13,733');
  });

  it('switches the theme and remembers it', async () => {
    open('/');
    await userEvent.click(screen.getByRole('button', { name: '라이트 테마로 바꾸기' }));
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(screen.getByRole('button', { name: '다크 테마로 바꾸기' })).toBeInTheDocument();
  });

  it('switches the language', async () => {
    open('/runs');
    await userEvent.click(screen.getByRole('button', { name: '언어 바꾸기: English' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Decision log' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main menu' })).toBeInTheDocument();
    await act(() => i18n.changeLanguage('ko'));
  });
});

describe('the search', () => {
  it('opens with Ctrl K, filters the menus and opens the chosen one with Enter', async () => {
    open('/');
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const dialog = await screen.findByRole('dialog', { name: '검색' });
    const box = within(dialog).getByRole('combobox', { name: '검색' });
    await userEvent.type(box, '판정');
    const options = within(dialog)
      .getAllByRole('option')
      .map((option) => option.textContent);
    expect(options).toEqual(['판정 이력결과 분석', 'AI 판정 엔진결과 분석']);
    await userEvent.keyboard('{ArrowDown}{Enter}');
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/engine'));
    expect(dialog).not.toHaveAttribute('open');
  });

  it('opens a run ID straight in the decision details', async () => {
    open('/');
    await userEvent.click(screen.getByRole('button', { name: '메뉴 · 실행 ID · 용어 검색' }));
    const box = within(await screen.findByRole('dialog', { name: '검색' })).getByRole('combobox');
    await userEvent.type(box, 'run-04cdd89264f7{Enter}');
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/runs/run-04cdd89264f7'));
  });
});

describe('the menu', () => {
  it('folds to the icon rail between 1024 and 1279 and keeps the names for assistive technology', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query === RAIL_QUERY,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }));
    const { container } = open('/runs');
    await screen.findByRole('heading', { level: 1 });
    expect(container.querySelector('[data-rail]')).not.toBeNull();
    expect(container.querySelector('[data-focus]')).toBeNull();
    const nav = screen.getByRole('navigation', { name: '주 메뉴' });
    expect(within(nav).getByRole('link', { name: '판정 이력' })).toHaveAttribute('title', '판정 이력');
  });

  it('opens as a drawer on narrow screens and closes when a menu is chosen', async () => {
    stubMedia(true);
    open('/');
    expect(screen.queryByRole('complementary')).toBeNull();
    const button = screen.getByRole('button', { name: '메뉴 열기' });
    await userEvent.click(button);
    const drawer = screen.getByRole('dialog', { name: 'Contexa · 라이브 데모' });
    expect(drawer).toHaveAttribute('open');
    await userEvent.click(within(drawer).getByRole('link', { name: '판정 이력' }));
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/runs'));
    expect(drawer).not.toHaveAttribute('open');
  });

  it('lists the groups in the visitor order with the foot menus last', async () => {
    open('/');
    const nav = await screen.findByRole('navigation', { name: '주 메뉴' });
    expect(
      within(nav)
        .getAllByRole('link')
        .map((link) => link.textContent),
    ).toEqual([
      '데모 시작',
      '계정 탈취 · 내부자 위협',
      'AI 에이전트 위임 남용',
      '요청 급증 대응',
      '정책 시뮬레이터',
      '판정 이력',
      'AI 판정 엔진',
      '탐지 방식 비교',
      '표준 벤치마크',
      '시나리오 검증',
      '도입 · 연동 가이드',
      '운영 지표',
      '제품 투어',
      '보안 용어집',
      '개인정보 처리방침',
    ]);
  });
});
