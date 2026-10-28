// The fingerprint of a recorded guide video (가이드영상-제작기획안.md 2.2절): what the recording showed, in a few bytes.
// It is kept in the manifest; guide-verify.mjs records the scenario again without a video and compares, so a change of a
// screen's words, of an anchor, of the scenario or of a caption names the videos that are out of date and the scene.
import { createHash } from 'node:crypto';

/** What a screen showed, with its whitespace collapsed and cut at 300 characters, so a small change of layout is not a change of words. */
export function normalizeText(text) {
  return text.replace(/\s+/g, ' ').trim().slice(0, 300);
}

/**
 * The fingerprint of a recording: the scenario, the caption sentences of the scenes in the language and what each scene's
 * screen showed (its path, its headline, the words of the focused part, the anchors found).
 */
export function fingerprintOf({ scenario, dictionary, observed, language }) {
  const body = JSON.stringify({
    language,
    scenario,
    captions: scenario.scenes.map((scene) => dictionary[scene.key] ?? null),
    labels: scenario.scenes.flatMap((scene) => (scene.labels ?? []).map((label) => dictionary[label.key] ?? null)),
    observed: observed.map((entry) => ({
      path: entry.path,
      title: normalizeText(entry.title),
      focus: normalizeText(entry.focus),
      anchors: [...entry.anchors],
    })),
  });
  return createHash('sha256').update(body).digest('hex').slice(0, 16);
}

/** Where what a screen shows now differs from what the recording saw, scene by scene. */
export function differences(recorded, now) {
  const found = [];
  recorded.forEach((before, index) => {
    const after = now[index];
    if (!after) {
      found.push({ scene: index + 1, what: 'missing', recorded: before.path, now: '' });
      return;
    }
    for (const what of ['path', 'title', 'focus']) {
      if (normalizeText(before[what]) !== normalizeText(after[what])) {
        found.push({ scene: index + 1, what, recorded: normalizeText(before[what]), now: normalizeText(after[what]) });
      }
    }
    if (before.anchors.join('|') !== after.anchors.join('|')) {
      found.push({ scene: index + 1, what: 'anchors', recorded: before.anchors.join('|'), now: after.anchors.join('|') });
    }
  });
  return found;
}
