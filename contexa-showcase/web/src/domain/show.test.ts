import { describe, expect, it } from 'vitest';
import type { LabCase, LabFact, LabOptions, LabRequest } from '../api/lab';
import type { LiveRunView } from '../api/types';
import attackScenario from '../../../showcase-portal/src/main/resources/scenarios/A3S.json';
import ownerScenario from '../../../showcase-portal/src/main/resources/scenarios/A3ST.json';
import {
  conclusion,
  decision,
  lanes,
  leakedThroughExisting,
  retryAnswer,
  SCENARIO,
  sceneRequest,
  secondsText,
} from './show';

describe('durations on the screen', () => {
  it('keeps the milliseconds of an answer under a second', () => {
    expect(secondsText(29)).toBe('0.029');
    expect(secondsText(999)).toBe('0.999');
    expect(secondsText(1000)).toBe('1.0');
    expect(secondsText(37083)).toBe('37.1');
  });
});

/** The lab options as the portal answers them for the two acts' cases, built from the scenario files themselves. */
const options = {
  employees: [
    {
      key: 'adm-a',
      role: 'ADMIN',
      displayName: 'Administrator A',
      department: 'IT administration',
      officeNetwork: '10.40.12.0/24',
      assignedProjects: ['PLM-OPS'],
      customersManaged: 0,
      roleAllows: {},
    },
  ],
  timeSlots: [{ slot: 'DAWN', representativeTime: '03:17' }],
  items: [],
  operations: [],
  cases: [],
  calls: [],
  assessmentReasons: [],
} as LabOptions;

type Scenario = typeof attackScenario | typeof ownerScenario;

function caseOf(scenario: Scenario): LabCase {
  const first = scenario.steps[0];
  return {
    key: scenario.key,
    version: scenario.version,
    title: scenario.title,
    classification: scenario.oracle.classification,
    steps: scenario.steps.length,
    conditions: {
      employee: scenario.protagonist,
      timeSlot: scenario.timeSlot,
      place: 'OFFICE',
      device: 'USUAL',
      operation: first?.operation ?? null,
      target: 'UNASSIGNED',
      items: first?.items ?? null,
      approval: scenario.facts.length > 0,
      ticket: 'NONE',
      claim: 'NONE',
      onCall: false,
    },
    facts: scenario.facts as unknown as LabFact[],
    requests: (scenario.steps as readonly Record<string, unknown>[]).map((step) => ({
      operation: String(step['operation']),
      project: typeof step['project'] === 'string' ? step['project'] : null,
      document: (step['document'] as LabRequest['document'] | undefined)
        ? ({ fact: null, ...(step['document'] as object) } as LabRequest['document'])
        : null,
      customer: null,
      items: typeof step['items'] === 'number' ? step['items'] : null,
      claimedTicket: null,
      visitorSends: step['visitorSends'] === true,
      // GB-500 is not among the projects of the employee (business database), as the portal answers it.
      target: 'UNASSIGNED' as const,
    })),
  };
}

function run(steps: LiveRunView['steps']): LiveRunView {
  return {
    liveRunId: 'live-1',
    scenario: 'A3S',
    status: 'RUNNING',
    queuePosition: 0,
    queueWaitSeconds: null,
    runId: 'run-1',
    readyMs: 900,
    steps,
    challenge: null,
    failure: null,
  };
}

describe('lanes of a live run', () => {
  it('shows a stream while it runs and the answer once it is in', () => {
    const state = lanes(
      run([
        {
          stepNo: 1,
          operation: 'EXPORT_STREAM',
          layers: { C1: { outcome: 'STOPPED', httpStatus: 403, deliveredItems: 0, elapsedMs: 27 } },
          streams: { A: { total: 4831, delivered: 1233, atMs: 10200 } },
        },
      ]),
    );
    expect(state.A).toEqual({ kind: 'streaming', delivered: 1233, total: 4831 });
    expect(state.C1).toEqual({
      kind: 'done',
      outcome: 'STOPPED',
      delivered: 0,
      httpStatus: 403,
      elapsedMs: 27,
      ruleId: null,
    });
    expect(state.D).toEqual({ kind: 'waiting' });
  });
});

describe('the engine decision and the conclusion of a scene', () => {
  const stages = [
    {
      type: 'CONTEXT_COLLECTED',
      atMs: 96,
      action: null,
      layer: null,
      riskScore: null,
      confidence: null,
      elapsedMs: null,
      mitre: null,
    },
    {
      type: 'LAYER1_COMPLETE',
      atMs: 2830,
      action: 'BLOCK',
      layer: 'LAYER1',
      riskScore: 0.92,
      confidence: 0.8,
      elapsedMs: 2734,
      mitre: 'T1530',
    },
    {
      type: 'DECISION_APPLIED',
      atMs: 2831,
      action: 'BLOCK',
      layer: 'LAYER1',
      riskScore: null,
      confidence: null,
      elapsedMs: null,
      mitre: null,
    },
  ];

  it('reads the applied action and when it took effect', () => {
    expect(decision(stages)).toEqual({ action: 'BLOCK', atMs: 2831, riskScore: 0.92, confidence: 0.8 });
    expect(decision(stages.slice(0, 2))).toBeNull();
  });

  it('calls a cut only from the engine marker and says when the data left before a holding decision', () => {
    const cut = {
      kind: 'done',
      outcome: 'CUT',
      delivered: 342,
      httpStatus: 200,
      elapsedMs: 2900,
      ruleId: null,
    } as const;
    expect(conclusion('attacker', cut, decision(stages), 4831)).toEqual({
      kind: 'cut',
      delivered: 342,
      total: 4831,
      atMs: 2831,
    });
    const passed = {
      kind: 'done',
      outcome: 'DELIVERED',
      delivered: 4831,
      httpStatus: 200,
      elapsedMs: 37000,
      ruleId: null,
    } as const;
    const challenge = { action: 'CHALLENGE', atMs: 2800, riskScore: 0.6, confidence: 0.7 };
    expect(conclusion('attacker', passed, challenge, 4831)).toEqual({
      kind: 'leakedThenLocked',
      delivered: 4831,
      action: 'CHALLENGE',
    });
    expect(conclusion('attacker', passed, { ...challenge, action: 'ALLOW' }, 4831)).toEqual({
      kind: 'missed',
      delivered: 4831,
    });
    expect(conclusion('owner', passed, null, 4831)).toEqual({ kind: 'completed', delivered: 4831 });
    expect(conclusion('attacker', { kind: 'waiting' }, null, 4831)).toBeNull();
  });
});

describe('the scenes say what the scenarios send', () => {
  it("reads each act's request and approval from its case and the employee record (H-03)", () => {
    expect(SCENARIO).toEqual({ attacker: attackScenario.key, owner: ownerScenario.key });
    const attacker = sceneRequest(caseOf(attackScenario), options);
    const owner = sceneRequest(caseOf(ownerScenario), options);
    for (const request of [attacker, owner]) {
      expect(request).toMatchObject({
        employee: 'adm-a',
        employeeName: 'Administrator A',
        officeNetwork: '10.40.12.0/24',
        slot: 'DAWN',
        time: '03:17',
        hour: 3,
        operation: attackScenario.steps[0]?.operation,
        project: attackScenario.steps[0]?.project,
        items: attackScenario.steps[0]?.items,
      });
    }
    expect(attacker?.approval).toBeNull();
    expect(attacker?.target, "the request's own target, never an assumed one").toBe('UNASSIGNED');
    const second = attackScenario.steps[1] as {
      operation: string;
      document: { project: string; type: string };
    };
    expect(attacker?.followUp, "the attacker's second try as the case defines it").toEqual({
      operation: second.operation,
      project: second.document.project,
      documentType: second.document.type,
    });
    expect(owner?.followUp).toBeNull();
    expect(owner?.approval).toMatchObject({
      kind: 'APPROVAL',
      approver: ownerScenario.facts[0]?.approver,
      maxItems: ownerScenario.facts[0]?.maxItems,
    });
  });

  it('has no request without the employee or the time slot of its case', () => {
    expect(sceneRequest(caseOf(attackScenario), { ...options, employees: [] })).toBeNull();
    expect(sceneRequest(caseOf(attackScenario), { ...options, timeSlots: [] })).toBeNull();
  });

  it('leaves the second try to the attacker: one GB-500 drawing, sent when the visitor presses', () => {
    const retry = attackScenario.steps[1];
    expect(retry).toMatchObject({ operation: 'DOCUMENT_DOWNLOAD', visitorSends: true });
    expect(retry?.document?.project).toBe('GB-500');
    expect(retry?.document?.type).toBe('DRAWING');
    expect(ownerScenario.steps).toHaveLength(1);
  });
});

describe('the attack counters and the second try', () => {
  const run = (
    layers: Record<string, unknown>,
    streams: Record<string, unknown> = {},
    stepNo = 1,
  ): LiveRunView =>
    ({
      liveRunId: 'live-1',
      scenario: 'A3S',
      status: 'RUNNING',
      queuePosition: 0,
      queueWaitSeconds: null,
      runId: 'run-1',
      readyMs: 900,
      steps: [{ stepNo, operation: 'EXPORT_STREAM', layers, streams }],
      challenge: null,
      failure: null,
    }) as LiveRunView;

  it('counts what left through existing security by the furthest of the two streams', () => {
    const state = lanes(
      run(
        {},
        { A: { total: 4831, delivered: 1200, atMs: 9000 }, B: { total: 4831, delivered: 1240, atMs: 9000 } },
      ),
    );
    expect(leakedThroughExisting(state)).toBe(1240);
  });

  it('reads the hold on the account from the rule Contexa recorded, never from the status alone (H-06)', () => {
    const second = (httpStatus: number, outcome: string, ruleId: string | null) =>
      lanes(run({ D: { outcome, httpStatus, deliveredItems: 0, elapsedMs: 40, ruleId } }, {}, 2), 2).D;
    expect(retryAnswer(second(403, 'STOPPED', 'ACCOUNT_BLOCKED'))).toBe('BLOCK');
    expect(retryAnswer(second(401, 'HELD', 'MFA_CHALLENGE_REQUIRED'))).toBe('CHALLENGE');
    expect(retryAnswer(second(401, 'HELD', 'ZERO_TRUST_CHALLENGE'))).toBe('CHALLENGE');
    expect(retryAnswer(second(403, 'STOPPED', 'Forbidden')), 'the application permission check').toBe(
      'OTHER',
    );
    expect(retryAnswer(second(403, 'STOPPED', null))).toBe('OTHER');
    expect(
      retryAnswer(
        lanes(
          run({ D: { outcome: 'DELIVERED', httpStatus: 200, deliveredItems: 1, elapsedMs: 40 } }, {}, 2),
          2,
        ).D,
      ),
    ).toBe('PASSED');
    expect(retryAnswer(lanes(run({}), 2).D)).toBeNull();
  });
});
