import { describe, expect, it } from 'vitest';
import en from '../i18n/en.json';
import ko from '../i18n/ko.json';
import {
  actScreens,
  actStart,
  DEFAULT_ROUTE,
  GROUPS,
  MORE_PATH,
  nextScreen,
  previousScreen,
  screenAt,
  shareAddress,
  skipTarget,
  topicOf,
  TOPICS,
} from './journey';

const books = { ko: ko as Record<string, string>, en: en as Record<string, string> };

/** The main flow of the final screen design (docs/showcase/최종화면-구현계획.md 2절, F0-1). */
describe('the main flow', () => {
  it('is seven groups of 25 addresses in the plan numbers, each address once (FU-3 added 4-4, IN-6 group 5)', () => {
    expect(DEFAULT_ROUTE.map((screen) => screen.number)).toEqual([
      '1-1',
      '1-2',
      '2-0',
      '2-1',
      '2-2',
      '2-3',
      '3-0',
      '3-1',
      '3-2',
      '3-3',
      '4-0',
      '4-1',
      '4-2',
      '4-3',
      '4-4',
      '5-0',
      '5-1',
      '5-2',
      '5-3',
      '6-0',
      '6-1',
      '6-2',
      '6-3',
      '7-1',
      '7-2',
    ]);
    expect(new Set(DEFAULT_ROUTE.map((screen) => screen.path)).size).toBe(DEFAULT_ROUTE.length);
    expect(DEFAULT_ROUTE[0]?.path).toBe('/');
    expect(DEFAULT_ROUTE.at(-1)?.path).toBe('/summary/next');
    expect(DEFAULT_ROUTE.every((screen) => screen.act === Number(screen.number.split('-')[0]))).toBe(true);
  });

  it('opens groups 2 to 6 with their cover and the first and last group without one', () => {
    for (const group of GROUPS) {
      const screens = actScreens(group);
      const covers = screens.filter((screen) => screen.type === 'T0');
      if (group === 1 || group === 7) {
        expect(covers, `group ${group}`).toHaveLength(0);
      } else {
        expect(covers, `group ${group}`).toHaveLength(1);
        expect(screens[0]?.type, `group ${group} cover`).toBe('T0');
      }
      expect(actStart(group)).toBe(screens[0]);
    }
  });

  it('names every screen, its group and its main button in both languages', () => {
    for (const screen of DEFAULT_ROUTE) {
      const keys = [`main.${screen.number}.name`];
      // A cover's button names its group; a send screen and the last screen have their own action.
      if (screen.type !== 'T0' && screen.type !== 'T3' && screen.number !== '7-2') {
        keys.push(`main.${screen.number}.cta`);
      }
      for (const [language, book] of Object.entries(books)) {
        for (const key of keys) {
          expect(book[key], `${language} ${key}`).toBeTruthy();
        }
      }
    }
    for (const group of GROUPS) {
      expect(books.ko[`group.${group}`]).toBeTruthy();
      expect(books.en[`group.${group}`]).toBeTruthy();
    }
  });

  it('walks back and on along the order, and skips from a cover to the next group', () => {
    expect(previousScreen('DEFAULT', '/')).toBeNull();
    expect(nextScreen('DEFAULT', '/')?.path).toBe('/intro/map');
    expect(nextScreen('DEFAULT', '/intro/map')?.path).toBe('/attack');
    expect(nextScreen('DEFAULT', '/attack/result')?.path).toBe('/evidence');
    expect(previousScreen('DEFAULT', '/normal')?.path).toBe('/evidence/verdict');
    expect(nextScreen('DEFAULT', '/normal/check')?.path).toBe('/insider');
    expect(nextScreen('DEFAULT', '/insider/reason')?.path).toBe('/compare');
    expect(skipTarget('DEFAULT', '/insider')?.path).toBe('/compare');
    expect(nextScreen('DEFAULT', '/summary/next')).toBeNull();
    expect(skipTarget('DEFAULT', '/attack')?.path).toBe('/evidence');
    expect(skipTarget('DEFAULT', '/compare')?.path).toBe('/summary');
    expect(skipTarget('DEFAULT', '/attack/request')).toBeNull();
    expect(screenAt('DEFAULT', '/lab')).toBeNull();
    expect(shareAddress('DEFAULT', '/compare/runs', 'https://demo')).toBe('https://demo/compare/runs');
  });
});

/** "Learn more": the screens of the flow before, walked by topic and ending back at the hub. */
describe('the topics of learn more', () => {
  it('holds each earlier screen once, apart from the main flow, as group 0', () => {
    const paths = TOPICS.flatMap((topic) => topic.screens.map((screen) => screen.path));
    expect(new Set(paths).size).toBe(paths.length);
    for (const path of paths) {
      expect(
        DEFAULT_ROUTE.some((screen) => screen.path === path),
        path,
      ).toBe(false);
      expect(screenAt('DEFAULT', path)?.act, path).toBe(0);
    }
  });

  it('names every screen of a topic for the next button, in both languages', () => {
    for (const topic of TOPICS) {
      for (const screen of topic.screens) {
        expect(books.ko[`more.name.${screen.id}`], screen.id).toBeTruthy();
        expect(books.en[`more.name.${screen.id}`], screen.id).toBeTruthy();
      }
    }
  });

  it('stays inside the topic and ends without a next screen, so the end leads to the hub', () => {
    expect(topicOf('/intro/how')?.id).toBe('learning');
    expect(nextScreen('DEFAULT', '/intro/how')?.path).toBe('/try/stack');
    expect(previousScreen('DEFAULT', '/intro/learning')).toBeNull();
    expect(nextScreen('DEFAULT', '/try/summary/learning')).toBeNull();
    expect(nextScreen('DEFAULT', '/try/timing/when')).toBeNull();
    expect(nextScreen('DEFAULT', '/intro/approaches')).toBeNull();
    expect(topicOf(MORE_PATH)).toBeNull();
  });
});
