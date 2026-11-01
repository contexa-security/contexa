import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, matchPath, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import {
  ALL_ITEMS,
  OLD_ADDRESSES,
  fillTarget,
  menuItemOf,
  oldBenchmarkTarget,
  oldDetailTarget,
} from './routes';
import { UxApp } from './UxApp';

/** Every route of App.tsx before UX-R1 (95) and the five covers it led on (journey.ts COVER_REDIRECTS). */
const OLD_APP_ROUTES = [
  '/adopt',
  '/agent',
  '/agent/burst',
  '/agent/confirm',
  '/agent/console',
  '/agent/end',
  '/agent/next',
  '/agent/reason',
  '/agent/request',
  '/agent/result',
  '/attack/console',
  '/attack/reason',
  '/attack/request',
  '/attack/result',
  '/benchmark',
  '/benchmark/agent',
  '/benchmark/approaches',
  '/benchmark/cases',
  '/benchmark/cases/:caseKey',
  '/benchmark/judgment',
  '/benchmark/limits',
  '/benchmark/prompt',
  '/benchmark/reasoning',
  '/choose',
  '/compare/change',
  '/compare/inside',
  '/compare/rule',
  '/compare/runs',
  '/deeper',
  '/end/:pairKey',
  '/evidence/map',
  '/evidence/prompt',
  '/evidence/verdict',
  '/explore',
  '/insider/console',
  '/insider/reason',
  '/insider/request',
  '/intro',
  '/intro/approaches',
  '/intro/approaches/where',
  '/intro/compare',
  '/intro/concept',
  '/intro/how',
  '/intro/how/rules',
  '/intro/learning',
  '/intro/learning/learned',
  '/intro/map',
  '/intro/order',
  '/lab',
  '/lab/agent',
  '/lab/before',
  '/lab/case',
  '/lab/change',
  '/lab/result',
  '/lab/rules',
  '/lab/send',
  '/library',
  '/more',
  '/normal/check',
  '/normal/console',
  '/normal/diff',
  '/normal/request',
  '/part/:part',
  '/person',
  '/person/next',
  '/privacy',
  '/replay/:pairKey',
  '/run/:runId/detail',
  '/runs/:runId/steps/:stepNo',
  '/stats',
  '/summary',
  '/summary/next',
  '/try',
  '/try/attacker/:step',
  '/try/follow',
  '/try/follow/end',
  '/try/owner/:step',
  '/try/prompt',
  '/try/stack',
  '/try/summary/adopt',
  '/try/summary/dilemma',
  '/try/summary/end',
  '/try/summary/learning',
  '/try/summary/learning/end',
  '/try/summary/quiz',
  '/try/summary/recap',
  '/try/summary/value',
  '/try/timing/:step',
  '/try/timing/end',
  '/videos',
  '/',
  '/attack',
  '/normal',
  '/insider',
  '/evidence',
  '/compare',
];

/** The new addresses a menu owns below its own (a case's step, a run, a benchmark). */
const DEEPER = [
  '/simulate/person/:caseKey/:step',
  '/simulate/agent/:caseKey/:step',
  '/runs/:runId',
  '/benchmarks/:bench',
];

function isNewAddress(pathname: string): boolean {
  return (
    ALL_ITEMS.some((item) => item.path === pathname) ||
    DEEPER.some((pattern) => matchPath(pattern, pathname) !== null)
  );
}

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
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

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal('fetch', () => Promise.resolve(new Response('{}', { status: 404 })));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the address table (UC-1, UC-2)', () => {
  it('has thirteen menus and two at the foot, each its own address', () => {
    expect(ALL_ITEMS).toHaveLength(15);
    expect(new Set(ALL_ITEMS.map((item) => item.path)).size).toBe(15);
  });

  it('gives every old address a new place that the new table opens', () => {
    for (const old of OLD_APP_ROUTES) {
      if (isNewAddress(old)) {
        continue;
      }
      const target = OLD_ADDRESSES[old];
      expect(target, `${old} has no new place`).toBeDefined();
      const filled = fillTarget(target ?? '', {
        caseKey: 'S13',
        pairKey: 'A3',
        part: '1',
        runId: 'run-1',
        stepNo: '2',
        step: 'scene',
      });
      const pathname = filled.split('?')[0] ?? '';
      expect(isNewAddress(pathname), `${old} → ${filled}`).toBe(true);
    }
  });

  it('names the menu of a deeper address', () => {
    expect(menuItemOf('/runs/run-1')?.id).toBe('runs');
    expect(menuItemOf('/simulate/person/S13/live')?.id).toBe('person');
    expect(menuItemOf('/')?.id).toBe('home');
    expect(menuItemOf('/design/ux')).toBeNull();
  });

  it('reads an old shared decision-details window', () => {
    expect(oldDetailTarget('?modal=detail&detailRun=run-9&detailStep=3&detailTab=prompt')).toBe(
      '/runs/run-9?tab=prompt&step=3',
    );
    expect(oldDetailTarget('?modal=detail')).toBeNull();
    expect(oldDetailTarget('?tab=x')).toBeNull();
  });

  it("keeps an old benchmark link's setting and group, and opens its window as a tab (DEC-53)", () => {
    const setting = 'a'.repeat(64);
    expect(oldBenchmarkTarget('/validation', `?setting=${setting}&suite=RULE_BLIND`)).toBe(
      `/validation?setting=${setting}&suite=RULE_BLIND`,
    );
    expect(oldBenchmarkTarget('/validation', '?modal=method')).toBe('/validation?tab=method');
    expect(oldBenchmarkTarget('/validation?tab=scenarios', '?modal=case&case=S13')).toBe(
      '/validation?tab=scenarios&case=S13',
    );
    expect(oldBenchmarkTarget('/validation', '?modal=approach&control=C1')).toBe(
      '/validation?tab=controls&control=C1',
    );
    expect(oldBenchmarkTarget('/validation?tab=limits', '')).toBe('/validation?tab=limits');
  });
});

describe('the application routes', () => {
  it.each([
    ['/attack/console', '/simulate/person/S13/live'],
    ['/normal/diff', '/simulate/person/S13T/result?tab=compare'],
    ['/runs/run-1/steps/2', '/runs/run-1?step=2'],
    ['/benchmark/cases/S16', '/validation?tab=scenarios&case=S16'],
    // DEC-42: the old window's "right handling" tab (answer) is the summary's; its rules tab is the prompt's.
    ['/summary?modal=detail&detailRun=run-9&detailTab=answer', '/runs/run-9?tab=summary'],
    ['/summary?modal=detail&detailRun=run-9&detailTab=rules&detailStep=2', '/runs/run-9?tab=prompt&step=2'],
    ['/no/such/address', '/'],
  ])('lead %s to %s', async (from, to) => {
    open(from);
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent(to));
  });

  it('opens every menu in the frame with its own heading and the menu item marked current', async () => {
    for (const item of ALL_ITEMS) {
      const { unmount } = open(item.path);
      const name = i18n.t(`ux.menu.${item.id}`);
      // A built screen opens with its own heading (the start of the demo its story, the threat simulation its first
      // step), a pending one with the menu's name.
      const heading =
        {
          home: /같은 계정/,
          person: '위협 시나리오 선택',
          agent: '위협 시나리오 선택',
          surge: '요청 급증 대응',
        }[item.id as string] ?? name;
      expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeInTheDocument();
      const nav = screen.getByRole('navigation', { name: '주 메뉴' });
      expect(within(nav).getByRole('link', { name })).toHaveAttribute('aria-current', 'page');
      unmount();
    }
    // Every menu opens its real screen since I-7 (fifteen screens, each loading its code): longer than one screen's test.
  }, 20_000);

  it('runs the threat simulations in focus mode with the menu folded to the rail', async () => {
    const { container, unmount } = open('/simulate/person/S13/review');
    await screen.findByRole('heading', { level: 1 });
    expect(container.querySelector('[data-focus]')).toHaveAttribute('data-rail', 'true');
    unmount();
    const policy = open('/simulate/policy');
    await screen.findByRole('heading', { level: 1 });
    expect(policy.container.querySelector('[data-focus]')).toBeNull();
    expect(policy.container.querySelector('[data-rail]')).toBeNull();
  });

  it('writes the breadcrumb from the menu group and the menu item', async () => {
    open('/runs');
    await screen.findByRole('heading', { level: 1 });
    const crumbs = screen.getByRole('navigation', { name: '현재 위치' });
    expect(
      within(crumbs)
        .getAllByRole('listitem')
        .map((item) => item.textContent),
    ).toEqual(['결과 분석', '판정 이력']);
    expect(within(crumbs).getByText('판정 이력')).toHaveAttribute('aria-current', 'page');
  });
});
