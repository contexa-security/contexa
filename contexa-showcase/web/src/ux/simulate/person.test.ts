import { beforeEach, describe, expect, it } from 'vitest';
import type { BeforeSendView } from '../../api/anatomy';
import type { LabCase, LabEmployee } from '../../api/lab';
import type { RunScore } from '../../api/types';
import i18n from '../../i18n';
import {
  authWords,
  companyClock,
  conclusionKey,
  contextChips,
  controlVerdict,
  decidingStep,
  deviceWords,
  evalOf,
  factCells,
  personCase,
  truthOf,
} from './person';

/** The portal's before-sending comparison of S13 as it answered on 2026-10-31 (GET /api/live/before/S13?step=1). */
const S13_BEFORE = {
  runId: 'run-78c1493c1e61',
  stepNo: 1,
  startedAt: null,
  companyTime: '2026-09-30T14:20:00Z',
  usualVsNow: [
    { dimension: 'accessHour', now: '14', inUsual: 'true', labels: ['SameAsBaseline'] },
    { dimension: 'device', now: 'Safari/18 on MAC', inUsual: 'false', labels: ['DeviationsFromBaseline'] },
    {
      dimension: 'authenticationType',
      now: 'PASSWORD+ONE_TIME_CODE',
      inUsual: 'true',
      labels: ['SameAsBaseline'],
    },
    { dimension: 'size', now: '480 items', inUsual: 'false', labels: ['DeviationsFromBaseline'] },
    { dimension: 'rate', now: null, inUsual: 'UNKNOWN - no usual rate in the view', labels: [] },
  ],
  usual: {},
  departures: [],
  departureCount: 2,
  comparedCount: 9,
  companyAdverse: [],
  companyAdverseCount: 0,
  company: {},
  companyFacts: [],
  businessFacts: [
    { code: 'ASSIGNED', value: 'HX-310' },
    { code: 'NO_APPROVAL', value: null },
    { code: 'ON_CALL', value: null },
  ],
  sensitivity: 'HIGH',
  sizeRatio: { items: 480, usualLargest: 15, times: 32 },
  boundary: null,
  minimumRules: null,
} as unknown as BeforeSendView;

const S13_CASE = {
  key: 'S13',
  classification: 'THREAT',
  steps: 1,
  requests: [{ operation: 'EXPORT', project: 'HX-310', document: null, items: 480 }],
  facts: [],
} as unknown as LabCase;

const ENG_K = { key: 'eng-k', displayName: 'Design engineer K' } as unknown as LabEmployee;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

describe('the person scenarios', () => {
  it('know the three scenarios and their pairs', () => {
    expect(personCase('S13')?.pair).toBe('S13T');
    expect(personCase('S16')?.experience).toBe('E3');
    expect(personCase('S99')).toBeNull();
    expect(truthOf('THREAT')).toBe('threat');
    expect(truthOf('UNCERTAIN')).toBe('undetermined');
  });
});

describe('the request facts', () => {
  it('write the recorded values in words', () => {
    expect(deviceWords('Safari/18 on MAC')).toBe('Safari 18 · macOS');
    expect(deviceWords('Edge/140 on WINDOWS')).toBe('Edge 140 · Windows');
    expect(deviceWords('something else')).toBe('something else');
    expect(authWords(i18n.t, 'PASSWORD+ONE_TIME_CODE')).toBe('비밀번호 + 일회용 코드');
    expect(companyClock(i18n.t, '2026-09-30T14:20:00Z')).toBe('수요일 14:20');
  });

  it('mark each fact against the baseline the engine received', () => {
    const cells = factCells(i18n.t, (n) => n.toLocaleString('ko-KR'), S13_BEFORE, S13_CASE, ENG_K);
    expect(cells.map((cell) => [cell.id, cell.value, cell.mark, cell.note])).toEqual([
      ['account', '엔지니어 K', null, null],
      ['time', '수요일 14:20', 'in', null],
      ['device', 'Safari 18 · macOS', 'out', null],
      ['auth', '비밀번호 + 일회용 코드', 'in', null],
      ['size', '480건', 'out', '기준선 최대 15건'],
    ]);
  });

  it('name the business context the lookup returned', () => {
    expect(contextChips(i18n.t, S13_BEFORE.businessFacts)).toEqual([
      'HX-310 담당',
      '승인 기록 없음',
      '당번 근무 중',
    ]);
  });
});

describe('the decisions on the screen', () => {
  it('read a rule control by its outcome and Contexa by its decision', () => {
    expect(controlVerdict('A', { outcome: 'DELIVERED', ruleId: null }, null)).toBe('ALLOW');
    expect(controlVerdict('C1', { outcome: 'STOPPED', ruleId: 'C1-NIGHT' }, null)).toBe('BLOCK');
    expect(controlVerdict('D', { outcome: 'HELD', ruleId: null }, null)).toBe('PENDING');
    expect(
      controlVerdict('D', { outcome: 'HELD', ruleId: null }, { finalAction: 'CHALLENGE', unresolved: false }),
    ).toBe('CHALLENGE');
    expect(
      controlVerdict('D', { outcome: 'HELD', ruleId: null }, { finalAction: 'CHALLENGE', unresolved: true }),
    ).toBe('NONE');
    expect(controlVerdict('D', { outcome: 'STOPPED', ruleId: 'ACCOUNT_BLOCKED' }, null)).toBe('PRIOR');
    expect(controlVerdict('B', null, null)).toBeNull();
  });

  it('grade the business results and pick the conclusion from the server score', () => {
    expect(evalOf('STOPPED')).toBe('correct');
    expect(evalOf('MISSED')).toBe('missed');
    expect(evalOf('HALTED')).toBe('falsePositive');
    expect(evalOf('NOT_SCORED')).toBeNull();
    const score = (result: string, action: string | null) =>
      ({
        business: { D: { result, exposedItems: 0, worstStep: 1 } },
        verdicts: [{ score: { finalAction: action } }],
      }) as unknown as RunScore;
    expect(conclusionKey(score('STOPPED', 'CHALLENGE'))).toBe('ux.result.conclusion.stoppedChallenge');
    expect(conclusionKey(score('STOPPED', 'BLOCK'))).toBe('ux.result.conclusion.stoppedBlock');
    expect(conclusionKey(score('PASSED', 'ALLOW'))).toBe('ux.result.conclusion.passed');
    expect(conclusionKey(score('MISSED', 'ALLOW'))).toBe('ux.result.conclusion.missed');
    expect(conclusionKey(score('UNRESOLVED', null))).toBe('ux.result.conclusion.unresolved');
  });

  it('finds the request a run was decided at: the first restriction, else the last decision', () => {
    const run = (...actions: (string | null)[]) =>
      ({
        verdicts: actions.map((action, index) => ({ score: { stepNo: index + 1, finalAction: action } })),
      }) as unknown as RunScore;
    expect(decidingStep(run('ALLOW', 'BLOCK', null))).toBe(2);
    expect(decidingStep(run('CHALLENGE'))).toBe(1);
    expect(decidingStep(run('ALLOW', 'ALLOW', 'ALLOW'))).toBe(3);
    expect(decidingStep(run())).toBe(1);
  });
});
