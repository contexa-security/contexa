import { describe, expect, it } from 'vitest';
import '../i18n';
import i18n from '../i18n';
import { replayFixture } from '../test/replayFixture';
import { required } from '../test/required';
import { refusalOf } from './live';
import { evidenceKinds, factLine } from './reasons';
import { exposureSeconds, itemsAt, streamState } from './stream';

const attack = required(replayFixture.scenes[0], 'attack scene');

describe('reason lines', () => {
  it('show only evidence kinds and facts they know', async () => {
    await i18n.changeLanguage('en');
    const t = i18n.t.bind(i18n);
    expect(evidenceKinds(attack.engineReason, t)).toEqual([
      'Usual pattern',
      'Permission',
      'Session',
      'Target resource',
    ]);
    expect(factLine({ code: 'NOT_ASSIGNED', value: 'GB-500' }, t)).toBe('Not assigned to GB-500');
    expect(factLine({ code: 'ITEMS', value: '4831' }, t)).toBe('4,831 items requested');
    expect(factLine({ code: 'UNKNOWN_FACT', value: null }, t)).toBeNull();
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
