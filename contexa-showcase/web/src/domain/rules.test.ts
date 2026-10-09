import { describe, expect, it } from 'vitest';
import type { RuleCase, RuleCaseStep } from './rules';
import {
  contexaBetter,
  DEFAULT_SETTINGS,
  isNight,
  recordRule,
  score,
  stoppedByContexa,
  stoppedByRules,
  thresholdRule,
} from './rules';

/** The rule inputs the two rule controls recorded for pair A3 (rec-a3-a/-l, 2026-10-05). */
const recordedAttack: RuleCaseStep = {
  stepNo: 1,
  operation: 'EXPORT',
  companyTime: '2026-09-30T03:17:00Z',
  c1Facts: { items: 4831, night: true, projectKey: 'GB-500', companyTime: '2026-09-30T03:17:00Z', lastAccessDate: null, accessDaysLast30: 0 },
  c1Outcome: 'STOPPED',
  c1Rule: 'C1-NIGHT',
  c2Facts: {
    items: 4831,
    oncall: { onCall: false },
    ticket: { covered: false, mismatches: ['NO_TICKET'] },
    approval: { covered: false, maxItems: 0, mismatches: ['NO_APPROVAL'] },
    assigned: { assigned: false },
    projectKey: 'GB-500',
    accessDaysLast30: 0,
  },
  c2Outcome: 'STOPPED',
  c2Rule: 'C2-NO-CONTEXT',
  contexaOutcome: 'DELIVERED',
  contexaVerdict: 'ALLOW',
};

const recordedWork: RuleCaseStep = {
  ...recordedAttack,
  c2Facts: { ...recordedAttack.c2Facts, approval: { covered: true, maxItems: 5000 } },
  c2Outcome: 'DELIVERED',
  c2Rule: 'C2-APPROVAL',
};

const attack: RuleCase = { scenario: 'A3', classification: 'THREAT', title: {}, runId: 'run-a', finishedAt: null, steps: [recordedAttack] };
const work: RuleCase = { scenario: 'A3T', classification: 'NORMAL', title: {}, runId: 'run-l', finishedAt: null, steps: [recordedWork] };

describe('the rule controls recomputed on the screen', () => {
  it('reproduce what the rule controls recorded, with the published settings', () => {
    for (const step of [recordedAttack, recordedWork]) {
      const c1 = thresholdRule(step, DEFAULT_SETTINGS);
      const c2 = recordRule(step, DEFAULT_SETTINGS);
      expect(c1.rule).toBe(step.c1Rule);
      expect(c1.allowed).toBe(step.c1Outcome === 'DELIVERED');
      expect(c2.rule).toBe(step.c2Rule);
      expect(c2.allowed).toBe(step.c2Outcome === 'DELIVERED');
    }
  });

  it('read the night window the way the server does, across midnight and within a day', () => {
    expect(isNight('2026-09-30T03:17:00Z', DEFAULT_SETTINGS)).toBe(true);
    expect(isNight('2026-09-30T22:00:00Z', DEFAULT_SETTINGS)).toBe(true);
    expect(isNight('2026-09-30T06:00:00Z', DEFAULT_SETTINGS)).toBe(false);
    expect(isNight('2026-09-30T03:17:00Z', { ...DEFAULT_SETTINGS, nightStart: 2, nightEnd: 4 })).toBe(true);
    expect(isNight('2026-09-30T03:17:00Z', { ...DEFAULT_SETTINGS, nightStart: 4, nightEnd: 4 })).toBe(false);
  });

  it('show the trade-off: loosening the night rule lets the attack through, tightening the records halts the work', () => {
    const loose = { ...DEFAULT_SETTINGS, nightStart: 0, nightEnd: 0, volumeLimit: 10000, dormant: false, approval: true };
    expect(stoppedByRules(attack, DEFAULT_SETTINGS)).toBe(true);
    expect(stoppedByRules(work, DEFAULT_SETTINGS)).toBe(true);
    expect(recordRule(recordedWork, { ...DEFAULT_SETTINGS, approval: false }).allowed).toBe(false);
    expect(thresholdRule(recordedAttack, loose).allowed).toBe(true);
  });

  it('confirm a named ticket the way the server does: it exists and covers the request', () => {
    const claimed = (exists: boolean, covered: boolean): RuleCaseStep => ({
      ...recordedAttack,
      c2Facts: {
        ...recordedAttack.c2Facts,
        oncall: { onCall: true },
        ticket: { covered },
        claim: { ticketKey: 'TCK-1', exists, coverage: { covered } },
      },
    });
    expect(recordRule(claimed(true, true), DEFAULT_SETTINGS).rule).toBe('C2-TICKET-ONCALL');
    expect(recordRule(claimed(false, false), DEFAULT_SETTINGS).rule).toBe('C2-FALSE-CLAIM');
    expect(recordRule(claimed(true, false), DEFAULT_SETTINGS).rule).toBe('C2-FALSE-CLAIM');
    expect(recordRule(claimed(false, false), { ...DEFAULT_SETTINGS, falseClaim: false }).rule).toBe('C2-NO-CONTEXT');
  });

  it('keep a request the role does not permit refused whatever the settings', () => {
    const refused: RuleCaseStep = {
      ...recordedAttack,
      operation: 'CUSTOMER_READ',
      c1Facts: { role: 'ENGINEER' },
      c1Rule: 'RBAC',
      c2Facts: { role: 'ENGINEER' },
      c2Rule: 'RBAC',
    };
    const loosest = { ...DEFAULT_SETTINGS, nightStart: 0, nightEnd: 0, dormant: false, external: false };
    expect(thresholdRule(refused, loosest)).toEqual({ allowed: false, rule: 'RBAC' });
    expect(recordRule(refused, loosest)).toEqual({ allowed: false, rule: 'RBAC' });
  });

  it('count stopped attacks and halted work, and open the scene only when Contexa does better', () => {
    expect(score([attack, work], (rule) => stoppedByRules(rule, DEFAULT_SETTINGS))).toEqual({
      attacksStopped: 1,
      attacks: 1,
      workHalted: 1,
      work: 1,
    });
    expect(stoppedByContexa(attack)).toBe(false);
    expect(contexaBetter([attack, work])).toBe(false);
    const heldAttack = { ...attack, steps: [{ ...recordedAttack, contexaOutcome: 'HELD', contexaVerdict: 'CHALLENGE' }] };
    expect(contexaBetter([heldAttack, work])).toBe(true);
  });
});
