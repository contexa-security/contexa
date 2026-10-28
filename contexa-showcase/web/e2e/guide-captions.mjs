// Writes the caption tracks of every recorded guide video again from public/guides/guides.json (the scene times the
// recording kept) and the dictionaries, without recording again (가이드영상-계획.md). The recording script writes them
// the same way.
// Usage (web folder): node e2e/guide-captions.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { LINE_LIMIT, LINE_LIMIT_NARROW, vtt } from './guideCaptions.mjs';

const OUT = 'public/guides';
const dictionaries = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
const manifest = JSON.parse(readFileSync(join(OUT, 'guides.json'), 'utf-8'));
for (const [id, video] of Object.entries(manifest)) {
  // The wide files, and beside them the ones cut for a phone (<id>.<lang>.m.vtt, 가이드영상-제작기획안.md 6.2절).
  video.captionsNarrow = {};
  for (const [language, file] of Object.entries(video.captions)) {
    writeFileSync(
      join(OUT, file),
      vtt(video.scenes, video.end, dictionaries[language], LINE_LIMIT[language]),
    );
    console.log(`${id} ${language}: ${file}`);
    const narrow = file.replace(/\.vtt$/, '.m.vtt');
    writeFileSync(
      join(OUT, narrow),
      vtt(video.scenes, video.end, dictionaries[language], LINE_LIMIT_NARROW[language]),
    );
    video.captionsNarrow[language] = narrow;
    console.log(`${id} ${language} phone: ${narrow}`);
  }
}
writeFileSync(join(OUT, 'guides.json'), `${JSON.stringify(manifest, null, 2)}
`);
