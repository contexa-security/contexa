// Records a guide video from its scenario (가이드영상-제작기획안.md 7.1절, G-7): one command re-makes a video, in Korean and in
// English, with its caption files and its manifest entry.
// Usage (web folder): node e2e/guide-record.mjs <id> [--lang ko|en|both] [--base <url>] [--out <dir>]
//   --out defaults to public/guides, where the site serves them; a trial recording goes to another folder.
import { recordGuide } from './guide/record.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const id = args.find((arg) => !arg.startsWith('--') && args[args.indexOf(arg) - 1]?.startsWith('--') !== true);
if (!id) {
  console.error('usage: node e2e/guide-record.mjs <id> [--lang ko|en|both] [--base <url>] [--out <dir>]');
  process.exit(2);
}
const languages = option('--lang', 'both') === 'both' ? ['ko', 'en'] : [option('--lang', 'ko')];
const base = option('--base', 'http://127.0.0.1:19180');
const out = option('--out', 'public/guides');

for (const language of languages) {
  const result = await recordGuide({ id, language, base, out });
  console.log(
    `${id} ${language}: ${result.file} ${result.durationSec}s, ${result.scenes.length} scenes, fingerprint ${result.fingerprint}`,
  );
}
