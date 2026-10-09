import { describe, expect, it } from 'vitest';
import {
  actStart,
  DEFAULT_ROUTE,
  INTRO_ROUTE,
  nextScreen,
  routeAt,
  screenAt,
  shareAddress,
  skipTarget,
} from './journey';

/** The two routes of the plan's 4절 (screen design v2.3 0-3, journey slide, D-17, D-33). */
describe('journey routes', () => {
  it('starts the default route at the hook and walks the four acts in order', () => {
    expect(DEFAULT_ROUTE[0]?.path).toBe('/');
    expect(DEFAULT_ROUTE.map((screen) => screen.act)).toEqual(
      [...DEFAULT_ROUTE.map((screen) => screen.act)].sort((left, right) => (left ?? 0) - (right ?? 0)),
    );
    expect(DEFAULT_ROUTE.at(-1)?.path).toBe('/try/summary/adopt');
    expect(new Set(DEFAULT_ROUTE.map((screen) => screen.path)).size).toBe(DEFAULT_ROUTE.length);
  });

  it('puts the fifteen teaser cards where the 0-3 table puts them, in that order', () => {
    expect(
      DEFAULT_ROUTE.filter((screen) => screen.teaser).map((screen) => [screen.id, screen.teaser]),
    ).toEqual([
      ['hook', 'HOOK_TRY'],
      ['e1-result', 'E1_RESULT_FACTS'],
      ['e1-reason', 'E1_REASON_MAILBOX'],
      ['act-end-1', 'E1_AFTER_RULES'],
      ['e2-result', 'E2_RESULT_DIFF'],
      ['g-rules', 'G_RULES_RESUME'],
      ['act-end-2', 'FOLLOW_LEARNED'],
      ['g-learn-why', 'LEARN_WHY_TAUGHT'],
      ['g-learned', 'G_LEARNED_FLOW'],
      ['g-how', 'G_HOW_LINES'],
      ['e1-prompt', 'E1_PROMPT_ASYNC'],
      ['sync-when', 'SYNC_WHEN_OBSERVATIONS'],
      ['act-end-3', 'LEARN_AFTER_FALSE_BLOCKS'],
      ['g-where', 'G_WHERE_C2'],
      ['dilemma', 'DILEMMA_DIFFERENCES'],
    ]);
    expect(DEFAULT_ROUTE.filter((screen) => screen.actEnd).map((screen) => screen.id)).toEqual([
      'act-end-1',
      'act-end-2',
      'act-end-3',
    ]);
  });

  it('shows the rules between Try 2 reasons and its identity check, and the follow-up map after it', () => {
    const ids = DEFAULT_ROUTE.map((screen) => screen.id);
    expect(ids.slice(ids.indexOf('e2-reason'), ids.indexOf('follow') + 1)).toEqual([
      'e2-reason',
      'g-rules',
      'e2-check',
      'follow',
    ]);
  });

  it('walks the concept path through nine steps with the prompt inside Try 1', () => {
    expect(INTRO_ROUTE[0]?.path).toBe('/intro');
    const steps = INTRO_ROUTE.map((screen) => screen.conceptStep ?? 0);
    expect(steps).toEqual([...steps].sort((left, right) => left - right));
    expect(new Set(steps)).toEqual(new Set([1, 2, 3, 4, 5, 6, 7, 8, 9]));
    const ids = INTRO_ROUTE.map((screen) => screen.id);
    expect(ids.indexOf('e1-prompt')).toBe(ids.indexOf('e1-reason') + 1);
    expect(ids.indexOf('e1-after')).toBe(ids.indexOf('e1-prompt') + 1);
    expect(INTRO_ROUTE.some((screen) => screen.id === 'hook')).toBe(false);
    // The concept path has no act-end cards (D-33).
    expect(INTRO_ROUTE.some((screen) => screen.actEnd && screen.id === 'act-end-1')).toBe(false);
  });

  it('skips to the next act on the default route and to the next step on the concept path', () => {
    expect(skipTarget('DEFAULT', '/try/attacker/compare')?.path).toBe(actStart(2).path);
    expect(skipTarget('DEFAULT', '/try/summary/recap')).toBeNull();
    expect(skipTarget('INTRO', '/intro')?.path).toBe('/intro/concept');
    expect(nextScreen('DEFAULT', '/')?.path).toBe('/try/attacker/scene');
    expect(screenAt('INTRO', '/')).toBeNull();
  });

  it('takes the route from the address, then from a screen only one route lists, then from the stored route', () => {
    expect(routeAt('/try/attacker/scene', 'intro', 'DEFAULT')).toBe('INTRO');
    expect(routeAt('/try/attacker/scene', 'default', 'INTRO')).toBe('DEFAULT');
    expect(routeAt('/intro', null, 'DEFAULT')).toBe('INTRO');
    expect(routeAt('/intro/compare', null, 'DEFAULT')).toBe('INTRO');
    expect(routeAt('/', null, 'INTRO')).toBe('DEFAULT');
    expect(routeAt('/try/attacker/end', null, 'INTRO')).toBe('DEFAULT');
    expect(routeAt('/intro/how', null, 'INTRO')).toBe('INTRO');
    expect(routeAt('/intro/how', null, 'DEFAULT')).toBe('DEFAULT');
  });

  it('keeps the route in a shared address', () => {
    expect(shareAddress('INTRO', '/intro/how', 'https://demo')).toBe('https://demo/intro/how?route=intro');
    expect(shareAddress('DEFAULT', '/try/stack', 'https://demo')).toBe('https://demo/try/stack');
  });
});
