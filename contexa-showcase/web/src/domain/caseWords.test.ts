import { describe, expect, it } from 'vitest';
import { inCurrentWords } from './caseWords';

describe('a case sentence in the approved words', () => {
  it('says 정상 사용자 and 추가 인증 wherever the definition kept the old words', () => {
    expect(inCurrentWords('그래서 이 사례는 엔진의 본인 확인도 맞는 대응으로 인정한다.', 'ko')).toBe(
      '그래서 이 사례는 엔진의 추가 인증도 맞는 대응으로 인정한다.',
    );
    expect(inCurrentWords('진짜 직원의 본인 확인', 'ko')).toBe('정상 사용자의 추가 인증');
  });

  it('leaves another language as it is', () => {
    expect(inCurrentWords('the engine identity check', 'en')).toBe('the engine identity check');
  });
});
