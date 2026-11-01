import { OLD_GLOSSARY_TERMS } from './glossary/terms';
import type { UxIconName } from './ui/Icon';

/**
 * The menu and the addresses of the new screens (기획안 4절, 구현계획서 3절): every menu and every tab has a fixed
 * address, so a screen can be cited, shared and opened straight. The old addresses lead to the new place that shows the
 * same thing (UC-2), so no link a visitor kept breaks.
 */
export type MenuId =
  | 'home'
  | 'person'
  | 'agent'
  | 'surge'
  | 'policy'
  | 'runs'
  | 'engine'
  | 'compare'
  | 'benchmarks'
  | 'validation'
  | 'adopt'
  | 'metrics'
  | 'tour'
  | 'glossary'
  | 'privacy';

export interface MenuItem {
  readonly id: MenuId;
  readonly path: string;
  readonly icon: UxIconName;
  /** A threat simulation runs in focus mode: the menu folds to the icon rail and the body centres (기획안 4.2). */
  readonly focus?: boolean;
}

export interface MenuGroup {
  readonly id: 'live' | 'simulate' | 'analysis' | 'validation' | 'adoption';
  readonly items: readonly MenuItem[];
}

export const MENU: readonly MenuGroup[] = [
  { id: 'live', items: [{ id: 'home', path: '/', icon: 'play' }] },
  {
    id: 'simulate',
    items: [
      { id: 'person', path: '/simulate/person', icon: 'user-round-x', focus: true },
      { id: 'agent', path: '/simulate/agent', icon: 'bot', focus: true },
      { id: 'surge', path: '/simulate/surge', icon: 'layers', focus: true },
      { id: 'policy', path: '/simulate/policy', icon: 'sliders-horizontal' },
    ],
  },
  {
    id: 'analysis',
    items: [
      { id: 'runs', path: '/runs', icon: 'list-checks' },
      { id: 'engine', path: '/engine', icon: 'cpu' },
      { id: 'compare', path: '/compare', icon: 'git-compare-arrows' },
    ],
  },
  {
    id: 'validation',
    items: [
      { id: 'benchmarks', path: '/benchmarks', icon: 'clipboard-check' },
      { id: 'validation', path: '/validation', icon: 'target' },
    ],
  },
  {
    id: 'adoption',
    items: [
      { id: 'adopt', path: '/adopt', icon: 'plug-zap' },
      { id: 'metrics', path: '/metrics', icon: 'activity' },
      { id: 'tour', path: '/tour', icon: 'circle-play' },
    ],
  },
];

/** The two menus at the foot of the side menu. */
export const FOOT: readonly MenuItem[] = [
  { id: 'glossary', path: '/glossary', icon: 'book-open-text' },
  { id: 'privacy', path: '/privacy', icon: 'shield-check' },
];

export const ALL_ITEMS: readonly MenuItem[] = [...MENU.flatMap((group) => group.items), ...FOOT];

/** The menu an address belongs to: the item whose path is the address or begins it (`/runs/run-1` → 판정 이력). */
export function menuItemOf(pathname: string): MenuItem | null {
  if (pathname === '/') {
    return ALL_ITEMS[0] ?? null;
  }
  return (
    ALL_ITEMS.find(
      (item) => item.path !== '/' && (pathname === item.path || pathname.startsWith(`${item.path}/`)),
    ) ?? null
  );
}

export function groupOf(item: MenuItem): MenuGroup | null {
  return MENU.find((group) => group.items.includes(item)) ?? null;
}

/** The person cases of the old flow by role (src/pages/main/mainCases.ts): attacker S13, owner S13T, insider S16. */
const S13 = '/simulate/person/S13';
const S13T = '/simulate/person/S13T';
const S16 = '/simulate/person/S16';

/**
 * Every address of the old application (App.tsx before UX-R1, 95 routes and the five covers) and the new address
 * that shows the same thing. `:name` in a target takes the old address's parameter of that name.
 */
export const OLD_ADDRESSES: Readonly<Record<string, string>> = {
  // The old start, its covers and hubs → the start of the demo
  '/choose': '/',
  '/intro': '/',
  '/intro/concept': '/',
  '/intro/compare': '/',
  '/intro/order': '/',
  '/intro/map': '/',
  '/explore': '/',
  '/try': '/',
  '/deeper': '/',
  '/more': '/',
  '/part/:part': '/',
  // The people's requests → ATO & insider threat (S13 compromised account, S13T legitimate user, S16 insider)
  '/person': '/simulate/person',
  '/person/next': '/simulate/person',
  '/attack': `${S13}/review`,
  '/attack/request': `${S13}/review`,
  '/attack/console': `${S13}/live`,
  '/attack/result': `${S13}/result`,
  '/attack/reason': `${S13}/result`,
  '/try/attacker/:step': `${S13}/review`,
  '/normal': `${S13T}/review`,
  '/normal/request': `${S13T}/review`,
  '/normal/console': `${S13T}/live`,
  '/normal/check': `${S13T}/result`,
  '/normal/diff': `${S13T}/result?tab=compare`,
  '/try/owner/:step': `${S13T}/review`,
  '/insider': `${S16}/review`,
  '/insider/request': `${S16}/review`,
  '/insider/console': `${S16}/live`,
  '/insider/reason': `${S16}/result`,
  '/compare/inside': `${S16}/result`,
  // The agents' requests → AI agent delegation abuse; the burst and the repeated read → request surge
  '/agent': '/simulate/agent',
  '/agent/next': '/simulate/agent',
  '/agent/request': '/simulate/agent',
  '/agent/console': '/simulate/agent',
  '/agent/reason': '/simulate/agent',
  '/agent/confirm': '/simulate/agent',
  '/agent/end': '/simulate/agent',
  '/agent/result': '/simulate/agent',
  '/agent/burst': '/simulate/surge',
  '/try/stack': '/simulate/surge',
  // The lab → policy simulator
  '/lab': '/simulate/policy',
  '/lab/case': '/simulate/policy?tab=compose',
  '/lab/change': '/simulate/policy?tab=compose',
  '/lab/before': '/simulate/policy?tab=compose',
  '/lab/send': '/simulate/policy?tab=compose',
  '/lab/result': '/simulate/policy?tab=compose',
  '/lab/rules': '/simulate/policy?tab=threshold',
  '/lab/agent': '/simulate/policy?tab=agent',
  '/library': '/simulate/policy',
  // Run records, replays and the summary of what was seen → decision log
  '/runs/:runId/steps/:stepNo': '/runs/:runId?step=:stepNo',
  '/run/:runId/detail': '/runs/:runId',
  '/replay/:pairKey': '/runs?pair=:pairKey',
  '/summary': '/runs',
  '/end/:pairKey': '/runs',
  '/try/summary/recap': '/runs',
  '/try/summary/quiz': '/runs',
  '/try/summary/value': '/runs',
  // How a decision is made, the baseline, the facts, the prompt, timing and follow-up → AI decision engine
  '/evidence': '/engine?tab=facts',
  '/evidence/map': '/engine?tab=facts',
  '/evidence/prompt': '/engine?tab=prompt',
  '/evidence/verdict': '/engine?tab=flow',
  '/intro/how': '/engine?tab=flow',
  '/intro/how/rules': '/engine?tab=flow',
  '/intro/learning': '/engine?tab=baseline',
  '/intro/learning/learned': '/engine?tab=baseline',
  '/try/summary/learning': '/engine?tab=baseline',
  '/try/summary/learning/end': '/engine?tab=baseline',
  '/try/timing/:step': '/engine?tab=flow',
  '/try/timing/end': '/engine?tab=flow',
  '/try/follow': '/engine?tab=flow',
  '/try/follow/end': '/engine?tab=flow',
  '/try/prompt': '/engine?tab=prompt',
  // The rules and the five approaches → detection comparison
  '/compare/rule': '/compare?tab=rule',
  '/compare/change': '/compare?tab=change',
  '/compare/runs': '/compare?tab=runs',
  '/intro/approaches': '/compare',
  '/intro/approaches/where': '/compare',
  '/try/summary/dilemma': '/compare?tab=rule',
  // The demo's own measurement → scenario validation; the operational numbers → operational metrics
  '/benchmark': '/validation',
  '/benchmark/approaches': '/validation?tab=controls',
  '/benchmark/cases': '/validation?tab=scenarios',
  '/benchmark/cases/:caseKey': '/validation?tab=scenarios&case=:caseKey',
  '/benchmark/judgment': '/validation?tab=quality',
  '/benchmark/reasoning': '/validation?tab=quality',
  '/benchmark/prompt': '/validation?tab=quality',
  '/benchmark/limits': '/validation?tab=limits',
  '/benchmark/agent': '/validation?tab=agent',
  '/stats': '/metrics',
  // Adoption and the guide videos
  '/summary/next': '/adopt',
  '/try/summary/adopt': '/adopt',
  '/try/summary/end': '/adopt',
  '/videos': '/tour',
};

/** The old decision-details window opened over any screen (`?modal=detail&detailRun=&detailStep=&detailTab=`). */
const OLD_DETAIL_TABS: Readonly<Record<string, string>> = {
  summary: 'summary',
  process: 'summary',
  received: 'evidence',
  rules: 'prompt',
  prompt: 'prompt',
  answer: 'summary',
  original: 'integrity',
};

/** Where an old shared decision-details link leads, or null when the address carries none. */
export function oldDetailTarget(search: string): string | null {
  const params = new URLSearchParams(search);
  const run = params.get('detailRun');
  if (params.get('modal') !== 'detail' || !run) {
    return null;
  }
  const next = new URLSearchParams();
  const tab = OLD_DETAIL_TABS[params.get('detailTab') ?? ''];
  if (tab) {
    next.set('tab', tab);
  }
  const step = params.get('detailStep');
  if (step) {
    next.set('step', step);
  }
  const query = next.toString();
  return `/runs/${encodeURIComponent(run)}${query ? `?${query}` : ''}`;
}

/**
 * Where an old glossary link (`?modal=glossary&term=`) leads (ST-87): the term of the same meaning in the security
 * glossary, or the glossary itself; null when the address carries no glossary window.
 */
export function oldGlossaryTarget(search: string): string | null {
  const params = new URLSearchParams(search);
  if (params.get('modal') !== 'glossary') {
    return null;
  }
  const term = OLD_GLOSSARY_TERMS[params.get('term') ?? ''];
  return term ? `/glossary?term=${term}` : '/glossary';
}

/** The new address for an old one with its parameters filled in (`/run/:runId/detail` + run-1 → `/runs/run-1`). */
/**
 * An old benchmark address on its way to the scenario validation (DEC-53): the measurement setting and the case group
 * it showed stay, and an old window opens as its tab (the method, a scenario, a control in detail).
 */
export function oldBenchmarkTarget(target: string, search: string): string {
  const old = new URLSearchParams(search);
  const [pathname = target, query = ''] = target.split('?');
  const next = new URLSearchParams(query);
  for (const kept of ['setting', 'suite']) {
    const value = old.get(kept);
    if (value) {
      next.set(kept, value);
    }
  }
  const modal = old.get('modal');
  if (modal === 'method' || modal === 'prompt-method') {
    next.set('tab', 'method');
  } else if (modal === 'case' && old.get('case')) {
    next.set('tab', 'scenarios');
    next.set('case', old.get('case') ?? '');
  } else if (modal === 'approach') {
    next.set('tab', 'controls');
    const control = old.get('control');
    if (control) {
      next.set('control', control);
    }
  }
  const joined = next.toString();
  return joined ? `${pathname}?${joined}` : pathname;
}

export function fillTarget(target: string, params: Readonly<Record<string, string | undefined>>): string {
  return target.replace(/:([A-Za-z]+)/g, (_, name: string) => encodeURIComponent(params[name] ?? ''));
}
