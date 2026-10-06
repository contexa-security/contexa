import { describe, expect, it } from 'vitest';
import '../i18n';
import i18n from '../i18n';
import type { Layer } from '../api/types';
import { replayFixture } from '../test/replayFixture';
import { required } from '../test/required';
import { refusalOf } from './live';
import { engineReasonLine, evidenceKinds, factLine, ruleReason } from './reasons';
import { exposureSeconds, itemsAt, streamState } from './stream';
import { timelineEntries, timelineSummary } from './timeline';

const attack = required(replayFixture.scenes[0], 'attack scene');
const legitimate = required(replayFixture.scenes[1], 'legitimate scene');

function find(scene: typeof attack, control: string): Layer {
  return required(
    scene.layers.find((layer) => layer.control === control),
    control,
  );
}

describe('reason lines', () => {
  it('describe each rule control from its own rule and facts', async () => {
    await i18n.changeLanguage('en');
    const t = i18n.t.bind(i18n);
    expect(ruleReason(find(attack, 'A'), t)).toBe('No WAF rule matched');
    expect(ruleReason(find(attack, 'B'), t)).toBe('Allowed for the ADMIN role');
    expect(ruleReason(find(attack, 'C1'), t)).toBe('Data hand-out at night (22:00-06:00)');
    expect(ruleReason(find(legitimate, 'C2'), t)).toBe('An approval covers this project and count');
    const volume = { ...find(attack, 'C1'), ruleId: 'C1-VOLUME' };
    expect(ruleReason(volume, t)).toBe('4,831 items at once, above the volume limit');
    const waf = { ...find(attack, 'A'), outcome: 'STOPPED' as const, ruleId: null };
    expect(ruleReason(waf, t)).toBe('Stopped by a WAF rule');
    expect(ruleReason({ ...find(attack, 'C2'), ruleId: 'SOMETHING-NEW' }, t)).toBe('No rule record');
  });

  it('localize the engine reason only when it is a contract sentence', async () => {
    await i18n.changeLanguage('ko');
    const t = i18n.t.bind(i18n);
    expect(engineReasonLine(find(attack, 'D'), attack.engineReason, t)).toBe(
      '권한 있음 · 평소 패턴은 짧음 · 구체적 위험 없음',
    );
    expect(engineReasonLine(find(legitimate, 'D'), legitimate.engineReason, t)).toBe('엔진 원문 근거 보기');
    const unresolved = {
      ...find(attack, 'D'),
      evidence: { ...find(attack, 'D').evidence, unresolved: true },
    };
    expect(engineReasonLine(unresolved, attack.engineReason, t)).toBe('기술 장애로 판정 미결');
    const refused = {
      ...find(attack, 'D'),
      evidence: { ...find(attack, 'D').evidence, decisionId: null, timing: 'STATIC_AUTHORIZATION' as const },
    };
    expect(engineReasonLine(refused, null, t)).toBe('엔진 이전의 권한 검사에서 거부');
  });

  it('show only evidence kinds and facts they know', async () => {
    await i18n.changeLanguage('en');
    const t = i18n.t.bind(i18n);
    expect(evidenceKinds(attack.engineReason, t)).toEqual([
      'Usual pattern',
      'Permission',
      'Session',
      'Target resource',
    ]);
    expect(factLine({ code: 'NOT_ASSIGNED', value: 'GB-500' }, t)).toBe('Not assigned to project GB-500');
    expect(factLine({ code: 'ITEMS', value: '4831' }, t)).toBe('4,831 items requested');
    expect(factLine({ code: 'UNKNOWN_FACT', value: null }, t)).toBeNull();
  });
});

describe('analysis timeline', () => {
  it('shows the stored offsets unchanged, the response on the same axis and when the decision took effect', async () => {
    await i18n.changeLanguage('en');
    const t = i18n.t.bind(i18n);
    const evidence = find(attack, 'D').evidence;

    const entries = timelineEntries(evidence, t);

    expect(entries.map((entry) => [entry.label, entry.atMs, entry.note])).toEqual([
      ['Request context collected', 38, null],
      ['First-pass analysis started', 38, null],
      ['First-pass analysis finished', 1666, 'ALLOW · 1,627 ms of analysis'],
      ['Decision applied', 1666, 'ALLOW'],
      ['Response returned', 1702, null],
    ]);
    expect(timelineSummary(evidence, t)).toBe('The decision took effect 36 ms before the response.');
  });

  it('says an asynchronous decision applies from the next request and names unknown events by their code', async () => {
    await i18n.changeLanguage('ko');
    const t = i18n.t.bind(i18n);
    const base = find(attack, 'D').evidence;
    const later = {
      ...base,
      responseMs: 37,
      timeline: [
        ...base.timeline,
        { type: 'NEW_STAGE', layer: null, action: null, atMs: 1700, elapsedMs: null },
      ],
    };

    expect(timelineSummary(later, t)).toBe(
      '응답이 나간 뒤 1,629 ms에 판정이 적용되어 다음 요청부터 효력이 있습니다.',
    );
    expect(timelineEntries(later, t).map((entry) => entry.label)).toEqual([
      '응답 반환',
      '요청 맥락 수집',
      '1차 분석 시작',
      '1차 분석 완료',
      '판정 적용',
      '엔진 이벤트 NEW_STAGE',
    ]);
    expect(timelineEntries(find(attack, 'C2').evidence, t)).toEqual([]);
    expect(timelineSummary(find(attack, 'C2').evidence, t)).toBeNull();
  });
});

describe('stream exposure', () => {
  const cut = {
    total: 4831,
    delivered: 412,
    firstLineMs: 38,
    endMs: 2610,
    cut: true,
    interrupted: false,
    samples: [
      [38, 1],
      [140, 17],
      [2610, 412],
    ] as const,
  };

  it('shows the last recorded count at a moment, never an interpolated one', () => {
    expect(itemsAt(cut.samples, 0)).toBe(0);
    expect(itemsAt(cut.samples, 38)).toBe(1);
    expect(itemsAt(cut.samples, 2000)).toBe(17);
    expect(itemsAt(cut.samples, 9999)).toBe(412);
  });

  it('counts exposure from the first item to the cut and names the state from the stored flags only', () => {
    expect(exposureSeconds(cut)).toBeCloseTo(2.572);
    expect(streamState(cut)).toBe('cut');
    expect(streamState({ ...cut, cut: false, interrupted: true })).toBe('interrupted');
    expect(streamState({ ...cut, cut: false })).toBe('done');
    expect(exposureSeconds({ ...cut, firstLineMs: null })).toBe(0);
  });
});

describe('gate refusals', () => {
  it('shows a pause for a full house, a spent allotment or no current template, never a dead end', () => {
    expect(refusalOf(409, 'BUSY')).toBe('paused');
    expect(refusalOf(503, 'ALLOTMENT')).toBe('paused');
    expect(refusalOf(503, 'TEMPLATE')).toBe('paused');
    expect(refusalOf(429, 'VISITOR_LIMIT')).toBe('dailyLimit');
    expect(refusalOf(503, 'ENGINE_UNAVAILABLE')).toBe('error');
  });
});
