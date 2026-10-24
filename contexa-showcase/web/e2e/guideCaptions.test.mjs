import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { captionLines, LINE_LIMIT, vtt } from './guideCaptions.mjs';

const dictionaries = {
  ko: JSON.parse(readFileSync('src/i18n/ko.json', 'utf-8')),
  en: JSON.parse(readFileSync('src/i18n/en.json', 'utf-8')),
};
const scripts = JSON.parse(readFileSync('src/components/guide/guides.json', 'utf-8'));
const manifest = JSON.parse(readFileSync('public/guides/guides.json', 'utf-8'));

// The guide videos' captions (가이드영상-계획.md): one short line at a time at the bottom of the video, so a caption
// never climbs over the recorded screen.
describe('the guide captions', () => {
  it('cut every scene line into lines within the limit that read back as the line itself', () => {
    for (const [language, dictionary] of Object.entries(dictionaries)) {
      for (const script of Object.values(scripts)) {
        for (const key of script.scenes) {
          const lines = captionLines(dictionary[key], LINE_LIMIT[language]);
          expect(lines.join(' '), key).toBe(dictionary[key]);
          for (const line of lines) {
            expect(line.length, `${language} ${line}`).toBeLessThanOrEqual(LINE_LIMIT[language]);
          }
        }
      }
    }
  });

  it('cut at a sentence end first, then at a comma unless a cut at a space saves more than one line', () => {
    expect(captionLines('하나 둘 셋. 넷 다섯.', 8)).toEqual(['하나 둘 셋.', '넷 다섯.']);
    // Commas take three lines where spaces take two: one more line keeps the clauses whole.
    expect(captionLines('가나, 다라마 바사, 아자', 9)).toEqual(['가나,', '다라마 바사,', '아자']);
    expect(captionLines('짧은 문장.', 28)).toEqual(['짧은 문장.']);
  });

  it('keep an English phrase together: no cut before "of" or after an article', () => {
    expect(captionLines('Each bar is the data a kind of security actually handed over.', 40)).toEqual([
      'Each bar is the data a kind of security',
      'actually handed over.',
    ]);
    expect(
      captionLines('The log below keeps each step with its real time since the request arrived.', 46),
    ).toEqual(['The log below keeps each step', 'with its real time since the request arrived.']);
  });

  it("keep a quoted name whole, while an apostrophe inside a word opens no quote", () => {
    expect(captionLines("결과를 예상한 뒤 '에이전트에게 맡기기'를 누릅니다.", 28)).toEqual([
      '결과를 예상한 뒤',
      "'에이전트에게 맡기기'를 누릅니다.",
    ]);
    // Read as an opening quote, "agent's" would push the cut back to after "the".
    expect(captionLines("Look at the agent's facts and then the rows", 32)).toEqual([
      "Look at the agent's facts",
      'and then the rows',
    ]);
  });

  it('give each line its share of the scene in turn, the last ending where the scene ends', () => {
    const text = vtt(
      [
        { key: 'a', start: 1 },
        { key: 'b', start: 5 },
      ],
      9,
      { a: '하나 둘 셋. 넷 다섯.', b: '끝.' },
      8,
    );
    expect(text).toBe(
      'WEBVTT\n\n1\n00:00:01.000 --> 00:00:03.333\n하나 둘 셋.\n\n2\n00:00:03.333 --> 00:00:05.000\n넷 다섯.\n\n' +
        '3\n00:00:05.000 --> 00:00:09.000\n끝.\n',
    );
  });

  it('ship caption files that match the recorded scene times and the dictionaries', () => {
    for (const [id, video] of Object.entries(manifest)) {
      for (const [language, file] of Object.entries(video.captions)) {
        const shipped = readFileSync(`public/guides/${file}`, 'utf-8');
        expect(shipped, `${id} ${language}`).toBe(
          vtt(video.scenes, video.end, dictionaries[language], LINE_LIMIT[language]),
        );
      }
    }
  });
});
