// Finds the guide videos that are out of date (가이드영상-제작기획안.md 2.2절, G-13): goes through every recorded video's
// scenario again without recording and compares what each screen shows now with what the recording saw. Prints the stale
// videos and the scene and the thing that differs; exits 1 when there is one.
// Usage (web folder): node e2e/guide-verify.mjs [--base <url>] [--dir <manifest folder>]
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { differences } from './guide/fingerprint.mjs';
import { recordGuide } from './guide/record.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const base = option('--base', 'http://127.0.0.1:19180');
const dir = option('--dir', 'public/guides');
const path = join(dir, 'guides.json');
const manifest = existsSync(path) ? JSON.parse(readFileSync(path, 'utf-8')) : {};

let stale = 0;
let checked = 0;
for (const [id, entry] of Object.entries(manifest)) {
  if ('file' in entry) continue; // a recording made before the scenarios: replaced, not checked
  for (const [language, video] of Object.entries(entry)) {
    if (!video.fingerprint) continue;
    checked += 1;
    const now = await recordGuide({ id, language, base, out: dir, dry: true });
    if (now.fingerprint === video.fingerprint) {
      console.log(`${id} ${language}: up to date`);
      continue;
    }
    stale += 1;
    console.log(`${id} ${language}: STALE`);
    for (const change of differences(video.observed, now.observed)) {
      console.log(`  scene ${change.scene} ${change.what}: "${change.recorded}" -> "${change.now}"`);
    }
    if (differences(video.observed, now.observed).length === 0) {
      console.log('  the scenario or a caption changed (the screens are the same)');
    }
  }
}
console.log(checked === 0 ? 'no recorded video with a fingerprint' : `${stale} of ${checked} recordings are stale`);
process.exitCode = stale === 0 ? 0 : 1;
