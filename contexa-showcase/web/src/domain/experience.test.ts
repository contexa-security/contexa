import { describe, expect, it } from 'vitest';
import type { LiveRunView } from '../api/types';
import { replayFixture } from '../test/replayFixture';
import { required } from '../test/required';
import {
  answerKey,
  ATTACK_SCENE,
  bothRight,
  changedFacts,
  changedFrom,
  isRight,
  liveLanes,
  outcomesOf,
  OWNER_SCENE,
  recordedLanes,
} from './experience';

function run(status: LiveRunView['status'], layers: LiveRunView['steps'][number]['layers']): LiveRunView {
  return {
    liveRunId: 'live-1',
    scenario: 'adm-a.DAWN.4831.NONE.USUAL',
    status,
    queuePosition: 0,
    runId: 'run-1',
    readyMs: 800,
    steps: [{ stepNo: 1, operation: 'EXPORT', layers }],
    challenge: null,
    failure: null,
  };
}

const delivered = { outcome: 'DELIVERED' as const, httpStatus: 200, deliveredItems: 4831, elapsedMs: 40 };
const stopped = { outcome: 'STOPPED' as const, httpStatus: 403, deliveredItems: 0, elapsedMs: 12 };

describe('the lanes of a live run', () => {
  it('fills the answers that arrived, sends the next control and keeps the rest waiting', () => {
    const lanes = liveLanes(run('RUNNING', { A: delivered, B: delivered }));
    expect(lanes.A).toEqual({ kind: 'done', answer: delivered });
    expect(lanes.C1).toEqual({ kind: 'sending' });
    expect(lanes.C2).toEqual({ kind: 'waiting' });
    expect(lanes.D).toEqual({ kind: 'waiting' });
    expect(outcomesOf(lanes)).toBeNull();
  });

  it('sends nothing while the space is signing in or before any run', () => {
    expect(liveLanes(run('STARTING', {})).A).toEqual({ kind: 'waiting' });
    expect(liveLanes(null).A).toEqual({ kind: 'waiting' });
  });

  it('reads a stored real run with what each control handed over', () => {
    const lanes = recordedLanes(required(replayFixture.scenes[0]));
    expect(lanes.A).toEqual({
      kind: 'done',
      answer: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 4831, elapsedMs: 12 },
    });
    expect(outcomesOf(lanes)).toEqual({ A: 'DELIVERED', B: 'DELIVERED', C1: 'STOPPED', C2: 'STOPPED', D: 'DELIVERED' });
  });
});

describe('right and wrong', () => {
  it('stops the attack and lets the legitimate work through', () => {
    expect(isRight('STOPPED', 'STOP')).toBe(true);
    expect(isRight('HELD', 'STOP')).toBe(true);
    expect(isRight('DELIVERED', 'STOP')).toBe(false);
    expect(isRight('DELIVERED', 'PASS')).toBe(true);
    expect(isRight('STOPPED', 'PASS')).toBe(false);
    expect(isRight('HELD', 'PASS')).toBe(false);
    expect(isRight('HELD', 'PASS', true)).toBe(true);
    expect(isRight('UNRESOLVED', 'STOP')).toBeNull();
  });

  it('names the controls that got both scenes right', () => {
    const attack = {
      outcomes: { A: 'DELIVERED', B: 'DELIVERED', C1: 'STOPPED', C2: 'STOPPED', D: 'HELD' } as const,
      servedAfterCheck: false,
    };
    const owner = {
      outcomes: { A: 'DELIVERED', B: 'DELIVERED', C1: 'STOPPED', C2: 'DELIVERED', D: 'HELD' } as const,
      servedAfterCheck: true,
    };
    expect(bothRight(attack, owner)).toEqual(['C2', 'D']);
    expect(bothRight(attack, { ...owner, servedAfterCheck: false })).toEqual(['C2']);
  });
});

describe('what changed in free play', () => {
  it('lists the changed facts and the controls whose outcome changed', () => {
    expect(changedFacts(ATTACK_SCENE, OWNER_SCENE)).toEqual(['ticket']);
    expect(changedFacts(OWNER_SCENE, { ...OWNER_SCENE, slot: 'AFTERNOON', items: 40 })).toEqual(['slot', 'items']);
    const before = { A: 'DELIVERED', B: 'DELIVERED', C1: 'STOPPED', C2: 'STOPPED', D: 'DELIVERED' } as const;
    expect([...changedFrom({ ...before, C1: 'DELIVERED' }, before)]).toEqual(['C1']);
    expect(changedFrom(before, null).size).toBe(0);
  });

  it('words a held request by its status: an identity check or a security review', () => {
    expect(answerKey({ outcome: 'HELD', httpStatus: 401, deliveredItems: 0, elapsedMs: 9 })).toBe('exp.lane.check');
    expect(answerKey({ outcome: 'HELD', httpStatus: 423, deliveredItems: 0, elapsedMs: 9 })).toBe('exp.lane.review');
    expect(answerKey(delivered)).toBe('exp.lane.delivered');
    expect(answerKey(stopped)).toBe('exp.lane.stopped');
  });
});
