import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { sceneSeconds } from '../guideCaptions.mjs';
import { LINE_LIMIT, LINE_LIMIT_NARROW } from '../guideCaptions.mjs';
import { anchorsOf, loadScenarios, scenarioSeconds, selectorProblems, validate } from './scenario.mjs';

const dictionaries = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
const list = JSON.parse(readFileSync('src/components/guide/guides.json', 'utf-8'));

function sources(folder) {
  return readdirSync(folder).flatMap((name) => {
    const path = join(folder, name);
    return statSync(path).isDirectory()
      ? sources(path)
      : /\.tsx$/.test(name) && !name.includes('.test.')
        ? [readFileSync(path, 'utf-8')]
        : [];
  });
}
const sourceText = sources('src').join('\n');

// 가이드영상-제작기획안.md 7.1절: a video is a scenario file; its selectors are the screens' own stable attributes, so a
// change of style never breaks it, and the recorder stops when a target is gone instead of recording the wrong thing.
describe('the guide scenarios', () => {
  const scenarios = loadScenarios('guides/scenarios');

  it('has a scenario for the videos that were written so far, named after a guide of the list', () => {
    expect(scenarios.length).toBeGreaterThan(0);
    for (const scenario of scenarios) {
      expect(list[scenario.id], scenario.id).toBeDefined();
    }
  });

  it('is valid: every scene has a caption key and a target, and the keys are the guide list ones in order', () => {
    for (const scenario of scenarios) {
      expect(validate(scenario), scenario.id).toEqual([]);
      expect(scenario.scenes.map((scene) => scene.key), scenario.id).toEqual(list[scenario.id].scenes);
    }
  });

  it('has the caption and the labels of every scene in both dictionaries', () => {
    for (const scenario of scenarios) {
      for (const scene of scenario.scenes) {
        for (const key of [scene.key, ...(scene.labels ?? []).map((label) => label.key)]) {
          for (const dictionary of Object.values(dictionaries)) {
            expect(dictionary[key], `${scenario.id} ${key}`).toBeTruthy();
          }
        }
      }
    }
  });

  // G-3: a name quoted in a caption ('데모 시작하기', 'Back') is a word of the screens, in that language.
  it('quotes only words the screens carry', () => {
    for (const scenario of scenarios) {
      for (const [language, dictionary] of Object.entries(dictionaries)) {
        const words = new Set(Object.values(dictionary));
        for (const scene of scenario.scenes) {
          for (const match of dictionary[scene.key].matchAll(/(?:^|\s)'([^']+)'/g)) {
            expect(words.has(match[1]), `${scenario.id} ${language}: '${match[1]}'`).toBe(true);
          }
        }
      }
    }
  });

  it('points only at stable attributes: no class name, no position', () => {
    for (const scenario of scenarios) {
      for (const selector of scenario.scenes.flatMap((scene) => [
        scene.focus,
        scene.point,
        scene.click,
        scene.wait,
        ...(scene.labels ?? []).map((label) => label.target),
        ...(scene.badges ?? []).map((badge) => badge.target),
      ])) {
        if (selector) {
          expect(selectorProblems(selector), `${scenario.id}: ${selector}`).toEqual([]);
        }
      }
    }
  });

  it('names selectors the sources carry: every data-guide anchor it uses is in a screen file', () => {
    for (const scenario of scenarios) {
      for (const anchor of anchorsOf(scenario)) {
        expect(sourceText, `${scenario.id}: data-guide="${anchor}"`).toContain(`data-guide="${anchor}"`);
      }
    }
  });

  it('gives each scene the time both caption files need, in each language', () => {
    for (const scenario of scenarios) {
      for (const language of ['ko', 'en']) {
        const total = scenarioSeconds(scenario, dictionaries[language], language);
        const needed = scenario.scenes.reduce((sum, scene) => {
          const text = dictionaries[language][scene.key];
          return sum + Math.max(sceneSeconds(text, language, LINE_LIMIT[language]), sceneSeconds(text, language, LINE_LIMIT_NARROW[language]));
        }, 0);
        expect(total, `${scenario.id} ${language}`).toBeGreaterThanOrEqual(needed);
      }
    }
  });
});

describe('the scenario rules', () => {
  it('rejects a selector made of a class name, a position or a generated name', () => {
    expect(selectorProblems('[class*="_track_"]')).not.toEqual([]);
    expect(selectorProblems('.card')).not.toEqual([]);
    expect(selectorProblems('li:nth-child(2)')).not.toEqual([]);
    expect(selectorProblems('main > div > button')).not.toEqual([]);
  });

  it('accepts the screens own attributes', () => {
    expect(selectorProblems('[data-guide="start-purpose"]')).toEqual([]);
    expect(selectorProblems('[data-choice="person"]')).toEqual([]);
    expect(selectorProblems('[data-zone="actions"] [data-main]')).toEqual([]);
    expect(selectorProblems('main h1')).toEqual([]);
  });

  it('collects the data-guide anchors of a scenario once each', () => {
    const scenario = {
      scenes: [
        { focus: '[data-guide="a"]', point: '[data-guide="b"]', labels: [{ target: '[data-guide="a"]', key: 'k' }] },
        { focus: '[data-zone="body"]' },
      ],
    };
    expect(anchorsOf(scenario)).toEqual(['a', 'b']);
  });

  it('reports what a scenario lacks', () => {
    expect(validate({ id: 'x', path: '/', scenes: [{ key: 'guide.x.a' }] })).toEqual(['x scene 1: no focus']);
    expect(validate({ id: 'x', scenes: [] })).toEqual(['x: no start path', 'x: no scenes']);
  });
});
