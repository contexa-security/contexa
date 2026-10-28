import { describe, expect, it } from 'vitest';
import { differences, fingerprintOf, normalizeText } from './fingerprint.mjs';

const scenario = {
  id: 'x',
  path: '/',
  scenes: [
    { key: 'guide.x.a', focus: '[data-zone="title"]' },
    { key: 'guide.x.b', focus: '[data-main]', click: '[data-main]' },
  ],
};
const dictionary = { 'guide.x.a': '첫째 문장', 'guide.x.b': '둘째 문장' };
const observed = [
  { path: '/', title: '제목', focus: '제목 소개', anchors: ['[data-zone="title"]'] },
  { path: '/', title: '제목', focus: '시작하기', anchors: ['[data-main]'] },
];

// 가이드영상-제작기획안.md 2.2절: the manifest keeps a fingerprint of what a video showed, so a change of a screen's words,
// of an anchor, of the scenario or of a caption tells which videos are out of date.
describe('the fingerprint of a recorded guide', () => {
  it('is the same for the same scenario, captions and screens', () => {
    expect(fingerprintOf({ scenario, dictionary, observed, language: 'ko' })).toBe(
      fingerprintOf({ scenario: { ...scenario }, dictionary: { ...dictionary }, observed: [...observed], language: 'ko' }),
    );
  });

  it('is a short hex string', () => {
    expect(fingerprintOf({ scenario, dictionary, observed, language: 'ko' })).toMatch(/^[0-9a-f]{16}$/);
  });

  it('changes when a screen word the video showed changes', () => {
    const changed = observed.map((entry, index) => (index === 1 ? { ...entry, focus: '체험 시작' } : entry));
    expect(fingerprintOf({ scenario, dictionary, observed: changed, language: 'ko' })).not.toBe(
      fingerprintOf({ scenario, dictionary, observed, language: 'ko' }),
    );
  });

  it('changes when a caption, the scenario or the language changes', () => {
    const base = fingerprintOf({ scenario, dictionary, observed, language: 'ko' });
    expect(fingerprintOf({ scenario, dictionary: { ...dictionary, 'guide.x.a': '다른 문장' }, observed, language: 'ko' })).not.toBe(base);
    expect(
      fingerprintOf({ scenario: { ...scenario, scenes: scenario.scenes.slice(0, 1) }, dictionary, observed, language: 'ko' }),
    ).not.toBe(base);
    expect(fingerprintOf({ scenario, dictionary, observed, language: 'en' })).not.toBe(base);
  });

  it('does not change for whitespace in what a screen showed', () => {
    const spaced = observed.map((entry) => ({ ...entry, focus: `  ${entry.focus.replace(' ', '   ')}\n` }));
    expect(fingerprintOf({ scenario, dictionary, observed: spaced, language: 'ko' })).toBe(
      fingerprintOf({ scenario, dictionary, observed, language: 'ko' }),
    );
  });
});

describe('what a screen showed', () => {
  it('collapses its whitespace and cuts it at 300 characters', () => {
    expect(normalizeText('  가나\n  다  ')).toBe('가나 다');
    expect(normalizeText('가'.repeat(400))).toHaveLength(300);
  });

  it('says which scenes differ from the recording', () => {
    const now = observed.map((entry, index) => (index === 1 ? { ...entry, focus: '체험 시작', anchors: [] } : entry));
    expect(differences(observed, now)).toEqual([
      { scene: 2, what: 'focus', recorded: '시작하기', now: '체험 시작' },
      { scene: 2, what: 'anchors', recorded: '[data-main]', now: '' },
    ]);
    expect(differences(observed, observed)).toEqual([]);
  });

  it('says when the scenes are not the same number', () => {
    expect(differences(observed, observed.slice(0, 1))).toEqual([{ scene: 2, what: 'missing', recorded: '/', now: '' }]);
  });
});
