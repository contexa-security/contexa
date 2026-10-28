import { describe, expect, it } from 'vitest';
import en from '../i18n/en.json';
import ko from '../i18n/ko.json';
import {
  COVER_REDIRECTS,
  DEFAULT_ROUTE,
  entryOf,
  MORE_PATH,
  nextScreen,
  otherTrack,
  previousScreen,
  screenAt,
  shareAddress,
  STEPS,
  topicOf,
  TOPICS,
  trackOf,
} from './journey';

const books = { ko: ko as Record<string, string>, en: en as Record<string, string> };

/**
 * The main flow of the choose-and-test design (docs/showcase/첫화면-선택형-체험-개선기획안.md 4절, 구현계획 NW-1): a start
 * that makes the visitor choose between the two tracks, the agent's and the person's, each walked by its own lane, with
 * the deeper screens behind a hub. Every screen of the old 33 stays (the six covers become the choosers).
 */
describe('the main flow', () => {
  it('holds 34 screens in the plan numbers, each address once', () => {
    expect(DEFAULT_ROUTE.map((screen) => screen.number)).toEqual([
      '1-1',
      'C-1',
      'H-1',
      '2-1',
      '2-2',
      '2-3',
      '2-4',
      '4-1',
      '4-2',
      '4-3',
      '5-1',
      '5-2',
      '5-3',
      'H-6',
      'A-1',
      '6-1',
      '6-2',
      '6-7',
      '6-3',
      'A-6',
      'D-1',
      '1-2',
      '3-1',
      '3-2',
      '3-3',
      '4-4',
      '6-4',
      '6-5',
      '6-6',
      '7-1',
      '7-2',
      '7-3',
      '8-1',
      '8-2',
    ]);
    expect(new Set(DEFAULT_ROUTE.map((screen) => screen.path)).size).toBe(DEFAULT_ROUTE.length);
    expect(new Set(DEFAULT_ROUTE.map((screen) => screen.id)).size).toBe(DEFAULT_ROUTE.length);
    expect(DEFAULT_ROUTE[0]?.path).toBe('/');
    // the portal keeps the id as the visitor's step: 1 to 40 of a-z, 0-9 and -
    expect(DEFAULT_ROUTE.every((screen) => /^[a-z0-9-]{1,40}$/.test(screen.id))).toBe(true);
    // the portal keeps the group as 0 to 8
    expect(DEFAULT_ROUTE.every((screen) => screen.act >= 0 && screen.act <= 8)).toBe(true);
  });

  it('has no cover: the landing is the start, the choosers and the next-choosers are the one type of choosing screen (T9)', () => {
    expect(DEFAULT_ROUTE.filter((screen) => screen.type === 'T0')).toHaveLength(0);
    expect(screenAt('DEFAULT', '/')?.type).toBe('T1');
    expect(DEFAULT_ROUTE.filter((screen) => screen.type === 'T9').map((screen) => screen.number)).toEqual([
      'C-1',
      'H-1',
      'H-6',
      'A-1',
      'A-6',
      'D-1',
    ]);
  });

  it('gives every screen its track, lane and, on a track, its step of six', () => {
    expect(screenAt('DEFAULT', '/')?.track).toBe('C');
    expect(screenAt('DEFAULT', '/choose')).toMatchObject({ track: 'C', lane: 'choose', step: null });
    expect(screenAt('DEFAULT', '/person')).toMatchObject({ track: 'H', lane: 'person', step: 1 });
    expect(screenAt('DEFAULT', '/attack/request')).toMatchObject({ track: 'H', lane: 'attack', step: 2 });
    expect(screenAt('DEFAULT', '/attack/console')?.step).toBe(3);
    expect(screenAt('DEFAULT', '/attack/result')?.step).toBe(4);
    expect(screenAt('DEFAULT', '/attack/reason')?.step).toBe(5);
    expect(screenAt('DEFAULT', '/person/next')).toMatchObject({ track: 'H', step: 6 });
    expect(screenAt('DEFAULT', '/agent')).toMatchObject({ track: 'A', lane: 'agent-pick', step: 1 });
    expect(screenAt('DEFAULT', '/agent/request')).toMatchObject({ track: 'A', lane: 'agent', step: 2 });
    expect(screenAt('DEFAULT', '/agent/result')?.step).toBe(4);
    expect(screenAt('DEFAULT', '/agent/reason')?.step).toBe(5);
    expect(screenAt('DEFAULT', '/agent/next')).toMatchObject({ track: 'A', step: 6 });
    expect(screenAt('DEFAULT', '/evidence/map')).toMatchObject({ track: 'C', lane: 'evidence', step: null });
    expect(
      DEFAULT_ROUTE.every((screen) => screen.step == null || (screen.step >= 1 && screen.step <= STEPS)),
    ).toBe(true);
    expect(STEPS).toBe(6);
    expect(trackOf('/attack/result')).toBe('H');
    expect(trackOf('/agent/console')).toBe('A');
    expect(trackOf('/summary')).toBe('C');
    expect(trackOf('/lab')).toBeNull();
  });

  it('names every screen and its main button in both languages', () => {
    for (const screen of DEFAULT_ROUTE) {
      const keys = [`main.${screen.number}.name`];
      // a send screen, a choosing screen and the last screen have their own action
      if (screen.type !== 'T3' && screen.type !== 'T9' && screen.number !== '8-2') {
        keys.push(`main.${screen.number}.cta`);
      }
      for (const [language, book] of Object.entries(books)) {
        for (const key of keys) {
          expect(book[key], `${language} ${key}`).toBeTruthy();
        }
      }
    }
  });

  it('walks inside a lane and ends it at the next-chooser of its track', () => {
    // the landing leads to the choosing of a track, which leads back to it
    expect(previousScreen('DEFAULT', '/')).toBeNull();
    expect(nextScreen('DEFAULT', '/')?.path).toBe('/choose');
    expect(previousScreen('DEFAULT', '/choose')?.path).toBe('/');
    expect(nextScreen('DEFAULT', '/choose')).toBeNull();
    expect(previousScreen('DEFAULT', '/person')?.path).toBe('/choose');
    expect(nextScreen('DEFAULT', '/person')).toBeNull();
    expect(previousScreen('DEFAULT', '/attack/request')?.path).toBe('/person');
    expect(nextScreen('DEFAULT', '/attack/request')?.path).toBe('/attack/console');
    expect(nextScreen('DEFAULT', '/attack/console')?.path).toBe('/attack/result');
    expect(nextScreen('DEFAULT', '/attack/result')?.path).toBe('/attack/reason');
    expect(nextScreen('DEFAULT', '/attack/reason')?.path).toBe('/person/next?from=attack');
    expect(nextScreen('DEFAULT', '/normal/diff')?.path).toBe('/person/next?from=normal');
    expect(nextScreen('DEFAULT', '/insider/reason')?.path).toBe('/person/next?from=insider');
    expect(previousScreen('DEFAULT', '/person/next')?.path).toBe('/person');
    expect(previousScreen('DEFAULT', '/agent')?.path).toBe('/choose');
    expect(previousScreen('DEFAULT', '/agent/request')?.path).toBe('/agent');
    expect(nextScreen('DEFAULT', '/agent/request')?.path).toBe('/agent/console');
    expect(nextScreen('DEFAULT', '/agent/console')?.path).toBe('/agent/result');
    expect(nextScreen('DEFAULT', '/agent/result')?.path).toBe('/agent/reason');
    expect(nextScreen('DEFAULT', '/agent/reason')?.path).toBe('/agent/next');
    expect(previousScreen('DEFAULT', '/agent/next')?.path).toBe('/agent');
    expect(nextScreen('DEFAULT', '/agent/next')).toBeNull();
    // the deeper screens lead back to the hub, whichever way they are walked
    expect(previousScreen('DEFAULT', '/deeper')).toBeNull();
    expect(previousScreen('DEFAULT', '/evidence/map')?.path).toBe('/deeper');
    expect(nextScreen('DEFAULT', '/evidence/map')?.path).toBe('/evidence/prompt');
    expect(nextScreen('DEFAULT', '/evidence/verdict')?.path).toBe('/deeper');
    expect(nextScreen('DEFAULT', '/compare/runs')?.path).toBe('/deeper');
    expect(nextScreen('DEFAULT', '/normal/check')?.path).toBe('/deeper');
    expect(nextScreen('DEFAULT', '/agent/burst')?.path).toBe('/deeper');
    expect(nextScreen('DEFAULT', '/summary')?.path).toBe('/summary/next');
    expect(nextScreen('DEFAULT', '/summary/next')).toBeNull();
    expect(screenAt('DEFAULT', '/lab')).toBeNull();
    expect(screenAt('DEFAULT', '/attack')).toBeNull();
    expect(shareAddress('DEFAULT', '/compare/rule', 'https://demo')).toBe('https://demo/compare/rule');
  });

  it("knows each track's entry and the other track's", () => {
    expect(entryOf('H')).toBe('/person');
    expect(entryOf('A')).toBe('/agent');
    expect(otherTrack('H')).toBe('A');
    expect(otherTrack('A')).toBe('H');
  });

  it('keeps the old cover addresses leading to the first screen of their track', () => {
    expect(COVER_REDIRECTS).toEqual({
      '/attack': '/attack/request',
      '/normal': '/normal/request',
      '/insider': '/insider/request',
      '/evidence': '/evidence/map',
      '/compare': '/compare/rule',
    });
    for (const target of Object.values(COVER_REDIRECTS)) {
      expect(screenAt('DEFAULT', target), target).not.toBeNull();
    }
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
