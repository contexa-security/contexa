/**
 * The approved words that replaced old ones (2026-10-19 user decision): every screen says "정상 사용자" and "추가 인증".
 * A case definition keeps the sentences it was measured with, since its hash ties every run to it, so its own
 * sentences (the ground truth's rationale and counterpoint) are shown in the approved words.
 */
const CURRENT_WORDS: Readonly<Record<string, readonly (readonly [string, string])[]>> = {
  ko: [
    ['진짜 직원', '정상 사용자'],
    ['본인 확인', '추가 인증'],
  ],
};

/** A case definition's sentence in the approved words of the language. */
export function inCurrentWords(text: string, language: string): string {
  return (CURRENT_WORDS[language] ?? []).reduce(
    (sentence, [old, now]) => sentence.split(old).join(now),
    text,
  );
}
