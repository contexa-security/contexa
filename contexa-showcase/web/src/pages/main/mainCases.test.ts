import { describe, expect, it } from 'vitest';
import type { LiveLayer } from '../../api/types';
import i18n from '../../i18n';
import {
  blindNote,
  contexaCell,
  decidedSteps,
  firstStopping,
  isScored,
  laneChip,
  runCell,
  splitChanged,
} from './mainCases';

// Review before the guide videos (2026-10-21): the 6-2 table and the changed prompt lines.
describe('the changed run on 6-2', () => {
  it('reads a scored result as recorded, and an unscored one falls back to the answer given', () => {
    for (const result of ['STOPPED', 'PARTLY_STOPPED', 'MISSED', 'PASSED', 'PASSED_AFTER_CHECK', 'HALTED']) {
      expect(isScored(result)).toBe(true);
    }
    for (const result of ['NOT_SCORED', 'UNRESOLVED', 'NONE', '', undefined]) {
      expect(isScored(result)).toBe(false);
    }
  });

  it('puts the lines the changed condition speaks to first and keeps the others apart', () => {
    const line = (label: string) => ({ label, before: ['a'], after: ['b'] });
    const changed = [
      line('Coverage'),
      line('PastRecord1'),
      line('Time'),
      line('DeviationsFromBaseline'),
      line('Size'),
    ];
    const time = splitChanged(changed, 'time');
    expect(time.related.map((item) => item.label)).toEqual(['Time', 'DeviationsFromBaseline']);
    expect(time.other.map((item) => item.label)).toEqual(['Coverage', 'PastRecord1', 'Size']);
    expect(splitChanged(changed, 'size').related.map((item) => item.label)).toEqual([
      'DeviationsFromBaseline',
      'Size',
    ]);
  });
});

// Review before the guide videos (2026-10-21), V-05 and V-06: Contexa's cell and a run without a ground truth.
describe("Contexa's cell and the approaches of a run without a ground truth", () => {
  const layer = (outcome: LiveLayer['outcome'], deliveredItems: number): LiveLayer => ({
    outcome,
    httpStatus: outcome === 'DELIVERED' ? 200 : 403,
    deliveredItems,
    elapsedMs: 10,
  });

  it("names Contexa by its own decision with the items that left, never by a result that reads 'blocked'", () => {
    expect(contexaCell('CHALLENGE', 0)).toEqual({ key: 'main.verdict.CHALLENGE', kind: 'auth', items: 0 });
    expect(contexaCell('ALLOW', 480)).toEqual({ key: 'main.verdict.ALLOW', kind: 'allow', items: 480 });
    expect(contexaCell('BLOCK', 2)).toEqual({ key: 'main.verdict.BLOCK', kind: 'block', items: 2 });
    expect(contexaCell(null, 0)).toBeNull();
    expect(contexaCell(undefined, 0)).toBeNull();
  });

  it("writes a run's cell: Contexa's decision with the items out, the other approaches' scored result", async () => {
    await i18n.changeLanguage('ko');
    const t = i18n.t.bind(i18n);
    const run = { engineAction: 'CHALLENGE', exposedItems: 0, business: { C1: 'MISSED', D: 'STOPPED' } };
    expect(runCell(t, 'ko', run, 'D')).toEqual({ kind: 'auth', words: '추가 인증 · 0건 나감' });
    expect(runCell(t, 'ko', run, 'C1')).toEqual({ kind: 'bad', words: t('main.result.MISSED') });
    // Without a decision of its own, Contexa's cell is its scored result.
    expect(runCell(t, 'ko', { ...run, engineAction: null }, 'D')).toEqual({
      kind: 'block',
      words: t('main.result.STOPPED'),
    });
  });

  it('reads an approach of a run with no ground truth by what it did, the same words for every approach', () => {
    expect(laneChip(layer('DELIVERED', 480), null)).toEqual({ key: 'main.lane.allowed', kind: 'allow' });
    expect(laneChip(layer('STOPPED', 0), null)).toEqual({ key: 'main.lane.stopped', kind: 'block' });
    expect(laneChip(layer('CUT', 120), null)).toEqual({ key: 'main.lane.cut', kind: 'auth' });
    expect(laneChip(layer('UNRESOLVED', 0), null)).toEqual({ key: 'main.lane.unresolved', kind: 'bad' });
    // A run of a case with a ground truth keeps its words: missed for an attack, allowed for the work.
    expect(laneChip(layer('DELIVERED', 480), true)).toEqual({ key: 'main.lane.through', kind: 'bad' });
    expect(laneChip(layer('DELIVERED', 480), false)).toEqual({ key: 'main.lane.allowed', kind: 'allow' });
  });
});

// V-02: the insider's request 5-3 opens on, and the ones the visitor can pick.
describe('the requests of the insider run on 5-3', () => {
  const verdict = (stepNo: number, finalAction: string | null) => ({ score: { stepNo, finalAction } });

  it('lists only the requests Contexa decided itself, in order', () => {
    expect(decidedSteps([verdict(1, 'ALLOW'), verdict(2, 'BLOCK'), verdict(3, null)])).toEqual([
      { stepNo: 1, action: 'ALLOW' },
      { stepNo: 2, action: 'BLOCK' },
    ]);
  });

  it('opens on the decision that kept the data in, else on the first decision', () => {
    expect(firstStopping(decidedSteps([verdict(1, 'ALLOW'), verdict(2, 'BLOCK'), verdict(3, null)]))).toBe(2);
    expect(firstStopping(decidedSteps([verdict(1, 'CHALLENGE')]))).toBe(1);
    expect(firstStopping(decidedSteps([verdict(1, 'ALLOW'), verdict(2, 'ALLOW')]))).toBe(1);
    expect(firstStopping([])).toBe(1);
  });
});

// V-12: the approval-record rule's footnote keeps the deck's words and adds a line only for the cases it never saw.
describe("the approval-record rule's footnote", () => {
  const blind = ['S13', 'S13T', 'S16'];

  it('adds that the rule-blind cases are not in the rule, naming one case or two', () => {
    expect(blindNote(blind, ['S13', 'S13T'])).toBe('main.4-3.blindNote');
    expect(blindNote(blind, ['S16'])).toBe('main.4-3.blindOne');
  });

  it('adds nothing for a case the rule was written from, or before the groups are known', () => {
    expect(blindNote(blind, ['S14'])).toBeNull();
    expect(blindNote(blind, ['S13', 'S14'])).toBeNull();
    expect(blindNote([], ['S13'])).toBeNull();
  });
});
