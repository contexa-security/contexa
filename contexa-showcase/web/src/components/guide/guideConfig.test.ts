import { describe, expect, it } from 'vitest';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import route from '../../journey/route.json';
import { GUIDE_IDS, guideEntry, guideForScreen, guideGroup, guideScreenPath, guidesOfKind } from './guideConfig';

/** The screens the plan marks as needing a video (docs/showcase/가이드영상-제작기획안.md 3.2절, 21 of the 34). */
const REQUIRED_SCREENS = [
  '1-1',
  '2-1',
  '2-2',
  '2-3',
  '2-4',
  '4-1',
  '4-2',
  '5-1',
  '5-2',
  '5-3',
  '6-1',
  '6-2',
  '6-7',
  '6-3',
  '4-4',
  '3-1',
  '3-2',
  '3-3',
  '7-1',
  '7-2',
  '7-3',
];
const RECOMMENDED_SCREENS = ['4-3', '6-4', '6-5', '6-6'];
/** The places outside the 34 screens that carry a video: the benchmark and the lab (3.2절 "화면 밖"). */
const OUTSIDE = ['benchmark', 'lab'];

describe('the guide videos of the plan', () => {
  it('lists the eleven required and the four recommended videos and keeps the two recorded old ones apart', () => {
    expect(guidesOfKind('required')).toHaveLength(11);
    expect(guidesOfKind('recommended')).toHaveLength(4);
    expect(guidesOfKind('legacy').sort()).toEqual(['agent', 'console']);
  });

  it('puts a link on exactly the 21 required screens and the benchmark and the lab', () => {
    const screens = guidesOfKind('required').flatMap((id) => guideEntry(id).screens);
    expect([...screens].sort()).toEqual([...REQUIRED_SCREENS, ...OUTSIDE].sort());
  });

  it('puts the recommended videos on their four screens', () => {
    const screens = guidesOfKind('recommended').flatMap((id) => guideEntry(id).screens);
    expect([...screens].sort()).toEqual([...RECOMMENDED_SCREENS].sort());
  });

  it('shows no old video on a screen: the two recorded before the new flow wait to be replaced', () => {
    for (const id of guidesOfKind('legacy')) {
      expect(guideEntry(id).screens).toEqual([]);
    }
  });

  it('names a screen of the journey for every screen it lists, and a screen belongs to one video', () => {
    const numbers = new Set(route.map((screen) => screen.number));
    const seen = new Map<string, string>();
    for (const id of GUIDE_IDS) {
      for (const screen of guideEntry(id).screens) {
        expect(numbers.has(screen) || OUTSIDE.includes(screen), `${id}: ${screen}`).toBe(true);
        expect(seen.get(screen), `${screen} is in ${seen.get(screen)} and ${id}`).toBeUndefined();
        seen.set(screen, id);
      }
    }
  });

  it('finds the video of a screen by its number', () => {
    expect(guideForScreen('1-1')).toBe('start');
    expect(guideForScreen('2-1')).toBe('request');
    expect(guideForScreen('5-2')).toBe('request');
    expect(guideForScreen('6-3')).toBe('agentResult');
    expect(guideForScreen('7-3')).toBe('benchmark');
    expect(guideForScreen('C-1')).toBeNull();
    expect(guideForScreen('D-1')).toBeNull();
    expect(guideForScreen(undefined)).toBeNull();
  });

  it('sorts the videos into the newcomer group and the track of their first screen', () => {
    expect(guideGroup('start')).toBe('S');
    expect(guideGroup('request')).toBe('H');
    expect(guideGroup('result')).toBe('H');
    expect(guideGroup('diff')).toBe('H');
    expect(guideGroup('delegate')).toBe('A');
    expect(guideGroup('agentResult')).toBe('A');
    expect(guideGroup('evidence')).toBe('C');
    expect(guideGroup('check')).toBe('C');
    expect(guideGroup('benchmark')).toBe('C');
    expect(guideGroup('lab')).toBe('C');
    expect(guideGroup('detail')).toBe('C');
  });

  it('finds the address of a screen of a video by its number, and of the two places outside the 34', () => {
    expect(guideScreenPath('2-1')).toBe('/attack/request');
    expect(guideScreenPath('6-3')).toBe('/agent/reason');
    expect(guideScreenPath('benchmark')).toBe('/benchmark');
    expect(guideScreenPath('lab')).toBe('/lab');
    expect(guideScreenPath('9-9')).toBeNull();
  });

  it('has a title in both dictionaries for every video, and every scene line it already lists', () => {
    for (const dictionary of [ko, en] as readonly Record<string, string>[]) {
      for (const id of GUIDE_IDS) {
        const entry = guideEntry(id);
        expect(dictionary[entry.title], entry.title).toBeTruthy();
        for (const key of entry.scenes) {
          expect(dictionary[key], key).toBeTruthy();
        }
      }
    }
  });
});
