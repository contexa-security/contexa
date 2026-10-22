import { beforeEach, describe, expect, it } from 'vitest';
import type { BeforeSendView, DecisionAnatomyView } from '../../api/anatomy';
import type { AnalysisStage, LiveLayer } from '../../api/types';
import i18n from '../../i18n';
import {
  atSeconds,
  contexaGaveKnown,
  eventLine,
  factRows,
  hasSecondPass,
  repeatLabel,
  resentOf,
} from './consoleData';

const layer = (outcome: LiveLayer['outcome'], deliveredItems = 1): LiveLayer => ({
  outcome,
  httpStatus: 200,
  deliveredItems,
  elapsedMs: 100,
});

// Review before the guide videos (2026-10-21): the console's counters and measured line.
describe('the console', () => {
  it('shows what Contexa handed over once it went out, even before the judgment arrives', () => {
    expect(contexaGaveKnown(layer('DELIVERED'), false)).toBe(true);
    expect(contexaGaveKnown(layer('CUT'), false)).toBe(true);
    expect(contexaGaveKnown(null, false)).toBe(false);
    expect(contexaGaveKnown(layer('STOPPED', 0), false)).toBe(false);
    expect(contexaGaveKnown(layer('STOPPED', 0), true)).toBe(true);
  });

  it('puts the resend of a live check on the request that was checked, not on the latest one', () => {
    const live = { stage: 'DONE', reissueStatus: 200, reissueDeliveredItems: 1 } as const;
    expect(resentOf(null, live, false, 401)).toEqual({ items: 1, status: 200 });
    expect(resentOf(null, live, false, 200)).toBeNull();
    expect(resentOf(null, live, true, 401)).toBeNull();
    expect(resentOf({ answered: true, reissue_status: 200, reissue_delivered: 1 }, null, true, 200)).toEqual({
      items: 1,
      status: 200,
    });
  });

  it('names the measured runs apart from the judgments, without "all" for a single one', () => {
    expect(repeatLabel({ CHALLENGE: 1 })).toEqual({
      key: 'main.console.repeat.one',
      action: 'CHALLENGE',
      n: 1,
    });
    expect(repeatLabel({ BLOCK: 3 })).toEqual({ key: 'main.console.repeat.all', action: 'BLOCK', n: 3 });
    expect(repeatLabel({ ALLOW: 1, BLOCK: 1, CHALLENGE: 0 })).toEqual({
      key: 'main.console.repeat.mixed',
      action: null,
      n: 2,
    });
  });
});

/** The engine input of the real user's run run-8e26a3f9bfa9 (S13T): only the size differs, the device is the usual. */
const OWNER_INPUT = {
  runId: 'run-8e26a3f9bfa9',
  stepNo: 1,
  startedAt: null,
  companyTime: null,
  usualVsNow: [
    { dimension: 'accessHour', now: '14', inUsual: 'true', labels: ['SameAsBaseline'] },
    { dimension: 'device', now: 'Edge/140 on WINDOWS', inUsual: 'true', labels: ['SameAsBaseline'] },
    { dimension: 'size', now: '480 items', inUsual: 'false', labels: ['DeviationsFromBaseline'] },
    {
      dimension: 'rate',
      now: null,
      inUsual: 'UNKNOWN - no usual rate in the view',
      labels: ['DeviationsFromBaseline'],
    },
  ],
  usual: {
    accessHour: { label: 'UsualHours', values: ['11', '12', '15', '16'] },
    device: { label: 'UsualDevices', values: ['Edge/140 on WINDOWS'] },
    size: { label: 'UsualExportSize', values: ['15'] },
  },
  departures: [],
  departureCount: 1,
  companyAdverse: [],
  companyAdverseCount: 0,
  company: {},
  companyFacts: [],
  businessFacts: [
    { code: 'ASSIGNED', value: 'HX-310' },
    { code: 'NO_APPROVAL', value: null },
    { code: 'NO_TICKET', value: null },
  ],
  sensitivity: 'HIGH',
  boundary: null,
  minimumRules: null,
} as unknown as BeforeSendView;

const stage = (type: string, action: string | null = null): AnalysisStage => ({
  type,
  atMs: null,
  action,
  layer: null,
  riskScore: 0.32,
  confidence: 0.82,
  elapsedMs: null,
  mitre: null,
});

/** The figures of the attack run run-e7177ebe6785: 49 learned requests, 21 of the last 7 days compared. */
const FIGURES = {
  figures: { workProfileWindow: '7d', workProfileObservations: 21, baselineBefore: 49 },
  interpretation: { calls: [] },
  promptLines: null,
} as unknown as DecisionAnatomyView;

// Review before the guide videos (2026-10-21): the console's fact check and its event log.
describe('the facts and the log of the console', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('ko');
  });
  const t = i18n.t.bind(i18n);

  it('writes the log times in the same unit as the rest of the screen (P-14)', () => {
    expect(atSeconds(t, 16440)).toBe('+16.44초');
    expect(atSeconds(t, 0)).toBe('+0.00초');
  });

  it('shows the device as the usual one when it did not differ, the fact that let the real user through (V-61)', () => {
    const rows = factRows(t, OWNER_INPUT);
    expect(rows.map((row) => row.id)).toEqual(['size', 'device', 'approval', 'sensitivity']);
    expect(rows.find((row) => row.id === 'device')?.mark).toBe('same');
  });

  it('marks a missing approval record apart from a difference (V-10)', () => {
    const approval = factRows(t, OWNER_INPUT).find((row) => row.id === 'approval');
    expect(approval?.mark).toBe('missing');
    expect(t('main.facts.mark.missing')).not.toContain('✕');
  });

  it('names the engine action in words beside its own word (P-15)', () => {
    const context = { anatomy: null, contexa: null, decision: null, language: 'ko', secondPass: true };
    expect(eventLine(t, stage('LAYER1_COMPLETE', 'CHALLENGE'), context)?.text).toContain(
      '추가 인증(CHALLENGE)',
    );
    expect(eventLine(t, stage('LAYER1_COMPLETE', 'ESCALATE'), context)?.text).toContain(
      t('main.event.action.ESCALATE'),
    );
  });

  it('calls a single analysis the AI analysis and names the first only when a second one came (P-41)', () => {
    const one = { anatomy: null, contexa: null, decision: null, language: 'ko', secondPass: false };
    expect(eventLine(t, stage('LAYER1_START'), one)?.text).toBe(t('main.event.analysis'));
    expect(eventLine(t, stage('LAYER1_START'), { ...one, secondPass: true })?.text).toBe(
      t('main.event.first'),
    );
    expect(hasSecondPass([stage('LAYER1_START'), stage('LAYER1_COMPLETE', 'CHALLENGE')])).toBe(false);
    expect(hasSecondPass([stage('LAYER1_START'), stage('LAYER1_COMPLETE', 'ESCALATE')])).toBe(true);
    expect(hasSecondPass([stage('LAYER2_START')])).toBe(true);
  });

  it('states the learned requests and the recent ones compared, in days (V-08)', () => {
    const context = { anatomy: FIGURES, contexa: null, decision: null, language: 'ko', secondPass: false };
    const line = eventLine(t, stage('CONTEXT_COLLECTED'), context)?.text ?? '';
    expect(line).toContain('학습 요청 49건 중 최근 7일 21건');
    expect(line).not.toContain('7d');
  });
});
