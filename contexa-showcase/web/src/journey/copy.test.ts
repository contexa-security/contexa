import { beforeAll, describe, expect, it } from 'vitest';
import i18n from '../i18n';
import type { Teaser, TeasersView } from '../api/teasers';
import { actEndSentence, teaserCopy } from './copy';
import { count, seconds } from './format';

const t = i18n.t.bind(i18n);

function view(...teasers: Teaser[]): TeasersView {
  return { computedAt: '2026-10-08T00:00:00Z', teasers };
}

function teaser(key: Teaser['key'], values: Record<string, unknown>, holds: boolean | null = null): Teaser {
  return { key, values, holds, source: { kind: 'MEASUREMENT', ref: 'protocol-1' }, missing: null };
}

beforeAll(async () => {
  await i18n.changeLanguage('ko');
});

/** Numbers are formatted one way everywhere (plan 1절 7); the server's values are never computed on. */
describe('number format', () => {
  it('writes seconds with one decimal from a second on and two below it', () => {
    expect(seconds(7964)).toBe('8.0');
    expect(seconds(53)).toBe('0.05');
    expect(count(4831, 'ko')).toBe('4,831');
  });
});

/** Teaser wording (work 19, plan 8절): the design's frame, the server's number, the fallback when it is not true. */
describe('teaser copy', () => {
  it('fills the design frame with the measured number', () => {
    const copy = teaserCopy(t, 'ko', 'HOOK_TRY', view(teaser('HOOK_TRY', { items: 4831 })), 0);
    expect(copy.question).toBe('직접 해 보면?');
    expect(copy.teaser).toBe('당신이 4,831건을 빼내 봅니다');
  });

  it('uses the approved fallback when the record does not make the sentence true', () => {
    const stopped = teaserCopy(
      t,
      'ko',
      'E1_AFTER_RULES',
      view(teaser('E1_AFTER_RULES', { runs: 3, refused: 3 }, true)),
      0,
    );
    const notAll = teaserCopy(
      t,
      'ko',
      'E1_AFTER_RULES',
      view(teaser('E1_AFTER_RULES', { runs: 3, refused: 2 }, false)),
      0,
    );
    expect(stopped.teaser).toBe('숫자 규칙은 막았습니다');
    expect(notAll.teaser).toBe('숫자 규칙은 3회 중 2회 막았습니다');
  });

  it('asks without a number when the source has none yet', () => {
    const missing: Teaser = {
      key: 'FOLLOW_LEARNED',
      values: {},
      holds: null,
      source: null,
      missing: 'NO_TEMPLATE',
    };
    const copy = teaserCopy(t, 'ko', 'FOLLOW_LEARNED', view(missing), 0);
    expect(copy.question).toBe('Contexa는 평소를 어떻게 알까?');
    expect(copy.teaser).toBeNull();
  });

  it('formats the seconds the server measured', () => {
    expect(
      teaserCopy(t, 'ko', 'G_RULES_RESUME', view(teaser('G_RULES_RESUME', { reissueMs: 53 }, true)), 0)
        .teaser,
    ).toBe('재개 0.05초');
    const prompt = teaserCopy(
      t,
      'ko',
      'E1_PROMPT_ASYNC',
      view(teaser('E1_PROMPT_ASYNC', { analysisMs: 7964, delivered: [4831, 4831, 4831] }, true)),
      0,
    );
    expect(prompt.question).toBe('판단에 8.0초, 그동안 자료는?');
    expect(prompt.teaser).toBe('4,831건이 나간 방식');
  });

  it("counts the visitor's differences for the dilemma card", () => {
    expect(teaserCopy(t, 'ko', 'DILEMMA_DIFFERENCES', undefined, 6).teaser).toBe('차이 6/6');
  });
});

/** The act-end sentence from the visitor's own run (work 18). */
describe('act-end sentence', () => {
  it("picks the frame by the run's result and Contexa's action", () => {
    expect(
      actEndSentence(t, 'ko', {
        act: 1,
        caseKey: 'A3',
        source: 'VISITOR_RUN',
        runId: 'run-1',
        values: {
          requested: 4831,
          engineAction: 'CHALLENGE',
          analysisMs: 7964,
          delivered: 0,
          result: 'STOPPED',
        },
      }),
    ).toBe(
      '당신은 정상 비밀번호로 4,831건을 빼내려 했고, Contexa는 8.0초 판단 뒤 추가 인증을 요구해 0건에서 멈췄습니다.',
    );
    expect(
      actEndSentence(t, 'ko', {
        act: 1,
        caseKey: 'A3',
        source: 'VISITOR_RUN',
        runId: 'run-2',
        values: {
          requested: 4831,
          engineAction: 'ALLOW',
          analysisMs: 6000,
          delivered: 4831,
          result: 'MISSED',
        },
      }),
    ).toBe('당신은 정상 비밀번호로 4,831건을 빼내려 했고, Contexa가 통과시켜 4,831건이 나갔습니다.');
  });

  it('states the second and third acts as their runs ended', () => {
    expect(
      actEndSentence(t, 'ko', {
        act: 2,
        caseKey: 'A3T',
        source: 'MEASUREMENT',
        runId: 'run-3',
        values: { result: 'PASSED', numberRule: 'HALTED' },
      }),
    ).toBe('정상 사용자의 결재된 내보내기는 통과시켰고, 고정 규칙은 같은 업무를 막았습니다.');
    expect(
      actEndSentence(t, 'ko', {
        act: 3,
        caseKey: 'A6T',
        source: 'VISITOR_RUN',
        runId: 'run-4',
        values: { from: 21, to: 25 },
      }),
    ).toBe('요청이 쌓이자 배운 요청이 21건에서 25건으로 늘었습니다.');
  });

  /** Part 4 (화면재편 4-4, P-2): when the judgment applied, what left before it and the next request, as recorded. */
  function timing(values: Record<string, unknown>) {
    return actEndSentence(t, 'ko', { act: 4, caseKey: 'A3A', source: 'VISITOR_RUN', runId: 'run-5', values });
  }

  it('states the fourth part by when the judgment applied and what happened to the next request', () => {
    const sent = { requested: 4831, engineAction: 'ESCALATE', applied: 'NEXT_REQUEST', analysisMs: 4199, delivered: 4831 };
    expect(timing({ ...sent, nextStopped: true })).toBe(
      '다음 요청부터 차단으로 보내자 판단 전에 4,831건이 나갔고, 다음 요청은 막혔습니다.',
    );
    expect(timing({ ...sent, delivered: 1200, nextStopped: false })).toBe(
      '다음 요청부터 차단으로 보내자 판단 전에 1,200건이 나갔고, 다음 요청도 나갔습니다.',
    );
    // A run without a second request says nothing about one.
    expect(timing({ ...sent, nextStopped: null })).toBe('다음 요청부터 차단으로 보내자 판단 전에 4,831건이 나갔습니다.');
    expect(timing({ ...sent, applied: 'BEFORE_RESPONSE', delivered: 0, nextStopped: null })).toBe(
      '판단을 응답 전에 적용해 판단이 끝날 때까지 응답을 붙잡았고, 0건이 나갔습니다.',
    );
  });

  it('falls back to the plain sentence when the record lacks what a frame needs', () => {
    const other = '이번 기록에서는 판단을 언제 적용했는지 읽지 못했습니다.';
    expect(timing({})).toBe(other);
    expect(timing({ applied: 'NEXT_REQUEST', delivered: null, nextStopped: true })).toBe(other);
    expect(timing({ applied: 'MID_RESPONSE', delivered: 4831, nextStopped: null })).toBe(other);
    expect(timing({ applied: null, delivered: 4831, nextStopped: true })).toBe(other);
  });
});
