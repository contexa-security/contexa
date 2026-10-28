// The scenario of a guide video (가이드영상-제작기획안.md 7.1절): a data file that says where the recording goes, what it
// points at and which caption sentence each scene shows. The recorder (guide-record.mjs) and the staleness check
// (guide-verify.mjs) read it; nothing else knows how a screen looks.
//
// {
//   "id": "start",                       the guide id of src/components/guide/guides.json
//   "path": "/",                         where the recording starts
//   "scenes": [{
//     "key": "guide.start.what",         the dictionary key of the caption sentence
//     "path": "/choose",                 go there first (optional; a click that leads on is usually better)
//     "wait": "[data-zone=\"body\"]",    wait until it is on the screen (optional)
//     "focus": "[data-zone=\"title\"]",  what the scene is about: lit, the rest dimmed
//     "point": "[data-main]",            where the pointer goes (optional; defaults to the focus)
//     "click": "[data-main]",            pressed when the caption has been read (optional)
//     "labels": [{ "target": "...", "key": "guide.start.label.x" }],   a short name beside a target (14 characters)
//     "badges": [{ "target": "...", "n": 1 }],                         the step number of a procedure
//     "min": 0                           the scene lasts at least this many seconds (optional)
//   }]
// }
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LINE_LIMIT, LINE_LIMIT_NARROW, sceneSeconds } from '../guideCaptions.mjs';

/** Every scenario file of a folder. */
export function loadScenarios(folder) {
  return readdirSync(folder)
    .filter((name) => name.endsWith('.scenario.json'))
    .sort()
    .map((name) => JSON.parse(readFileSync(join(folder, name), 'utf-8')));
}

/** What a scenario lacks, one sentence each; an empty list when it can be recorded. */
export function validate(scenario) {
  const problems = [];
  const id = scenario.id ?? '?';
  if (!scenario.path) problems.push(`${id}: no start path`);
  if (!Array.isArray(scenario.scenes) || scenario.scenes.length === 0) {
    problems.push(`${id}: no scenes`);
    return problems;
  }
  scenario.scenes.forEach((scene, index) => {
    if (!scene.key) problems.push(`${id} scene ${index + 1}: no caption key`);
    if (!scene.focus) problems.push(`${id} scene ${index + 1}: no focus`);
  });
  return problems;
}

const COMPOUND = /(?:[^\s[]|\[[^\]]*\])+/g;
const STABLE =
  /^(?:[a-z][a-z0-9]*)?(?:\[(?:data-[a-z-]+|role|aria-[a-z-]+)(?:[~|^$*]?="[^"]*")?\])*$/;

/**
 * Why a selector would break when a screen's style changes. A scenario points only at what the screens carry on
 * purpose: a tag name and `data-*`, `role` and `aria-*` attributes, never a class name, a position, an id or a child path.
 */
export function selectorProblems(selector) {
  const problems = [];
  const compounds = selector.match(COMPOUND) ?? [];
  if (compounds.length === 0) return ['empty'];
  for (const compound of compounds) {
    if (compound === '>' || compound === '+' || compound === '~') problems.push(`combinator ${compound}`);
    else if (!STABLE.test(compound)) problems.push(`not a stable name: ${compound}`);
  }
  return problems;
}

function targetsOf(scene) {
  return [
    scene.focus,
    scene.point,
    scene.click,
    scene.wait,
    ...(scene.labels ?? []).map((label) => label.target),
    ...(scene.badges ?? []).map((badge) => badge.target),
  ].filter(Boolean);
}

/** The `data-guide` anchors a scenario points at, once each, in the order they come. */
export function anchorsOf(scenario) {
  const anchors = [];
  for (const scene of scenario.scenes) {
    for (const target of targetsOf(scene)) {
      for (const match of target.matchAll(/\[data-guide="([^"]+)"\]/g)) {
        if (!anchors.includes(match[1])) anchors.push(match[1]);
      }
    }
  }
  return anchors;
}

/** How long each scene is given, in a language: the time both caption files (wide and phone) need to be read, or its own minimum. */
export function sceneDurations(scenario, dictionary, language) {
  return scenario.scenes.map((scene) => {
    const text = dictionary[scene.key];
    return Math.max(
      sceneSeconds(text, language, LINE_LIMIT[language]),
      sceneSeconds(text, language, LINE_LIMIT_NARROW[language]),
      scene.min ?? 0,
    );
  });
}

export function scenarioSeconds(scenario, dictionary, language) {
  return sceneDurations(scenario, dictionary, language).reduce((sum, seconds) => sum + seconds, 0);
}
