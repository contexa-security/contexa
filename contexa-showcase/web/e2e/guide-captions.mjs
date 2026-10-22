// Writes the caption tracks of every recorded guide video again from public/guides/guides.json (the scene times the
// recording kept) and the dictionaries, without recording again (가이드영상-계획.md). The recording script writes them
// the same way.
// Usage (web folder): node e2e/guide-captions.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { LINE_LIMIT, vtt } from './guideCaptions.mjs';

const OUT = 'public/guides';
const dictionaries = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
const manifest = JSON.parse(readFileSync(join(OUT, 'guides.json'), 'utf-8'));
for (const [id, video] of Object.entries(manifest)) {
  for (const [language, file] of Object.entries(video.captions)) {
    writeFileSync(
      join(OUT, file),
      vtt(video.scenes, video.end, dictionaries[language], LINE_LIMIT[language]),
    );
    console.log(`${id} ${language}: ${file}`);
  }
}
