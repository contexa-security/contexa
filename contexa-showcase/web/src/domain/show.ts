import type { LabCase, LabFact, LabOptions } from '../api/lab';
import type { AnalysisStage, LiveRunView } from '../api/types';
import type { BusinessOutcome, ControlId } from './verdict';
import { CONTROL_ORDER } from './verdict';

/**
 * The scenes of the final demo (docs/showcase/화면설계서.md): the attacker and the real owner send the same streamed
 * export, and the screen shows what each security approach did with it as it happens. Every value here comes from
 * the live run, the engine's analysis events and the learned baseline; nothing is made up for the screen.
 */

export type Role = 'attacker' | 'owner';

/** The designed case each act sends: the attacker's export and the real owner's approved transfer. */
export const SCENARIO: Readonly<Record<Role, string>> = { attacker: 'A3S', owner: 'A3ST' };

/**
 * The first request of a scene as its case defines it (H-03): who sends it, when, from where, and what it asks for.
 * Every value is read from the portal's case and employee records (/api/lab/options); nothing is copied here.
 */
export interface SceneRequest {
  readonly employee: string;
  readonly employeeName: string;
  readonly role: string;
  readonly officeNetwork: string;
  /** The case's time slot (DAWN, MORNING...) and its company time ("03:17"). */
  readonly slot: string;
  readonly time: string;
  readonly hour: number;
  readonly place: string | null;
  readonly device: string | null;
  readonly operation: string;
  /** Whether the target belongs to the employee's work (ASSIGNED, UNASSIGNED), as the case defines it. */
  readonly target: string | null;
  readonly project: string | null;
  readonly items: number | null;
  /** The approval the case records in the business database, when it records one. */
  readonly approval: LabFact | null;
  /** The request the visitor sends next in the same run (the attacker's second try), as the case defines it. */
  readonly followUp: {
    readonly operation: string;
    readonly project: string | null;
    readonly documentType: string | null;
  } | null;
}

export function sceneRequest(labCase: LabCase, options: LabOptions): SceneRequest | null {
  const request = labCase.requests[0];
  const employee = options.employees.find((candidate) => candidate.key === labCase.conditions.employee);
  const slot = options.timeSlots.find((candidate) => candidate.slot === labCase.conditions.timeSlot);
  if (!request || !employee || !slot) {
    return null;
  }
  return {
    employee: employee.key,
    employeeName: employee.displayName,
    role: employee.role,
    officeNetwork: employee.officeNetwork,
    slot: slot.slot,
    time: slot.representativeTime,
    hour: Number(slot.representativeTime.slice(0, 2)),
    place: labCase.conditions.place,
    device: labCase.conditions.device,
    operation: request.operation,
    target: request.target ?? labCase.conditions.target,
    project: request.project,
    items: request.items,
    approval: labCase.facts.find((fact) => fact.kind === 'APPROVAL') ?? null,
    followUp: followUpOf(labCase),
  };
}

function followUpOf(labCase: LabCase): SceneRequest['followUp'] {
  const next = labCase.requests.find((request, index) => index > 0 && request.visitorSends);
  if (!next) {
    return null;
  }
  return {
    operation: next.operation,
    project: next.project ?? next.document?.project ?? null,
    documentType: next.document?.type ?? null,
  };
}

/**
 * A duration in seconds as the screen states it: one decimal from a second on, milliseconds below it, so a 29 ms answer
 * reads 0.029 and never 0.0.
 */
export function secondsText(ms: number): string {
  return ms >= 1000 ? (ms / 1000).toFixed(1) : (ms / 1000).toFixed(3);
}

/** What one approach's lane shows while the run goes. */
export type LaneState =
  | { readonly kind: 'waiting' }
  | { readonly kind: 'streaming'; readonly delivered: number; readonly total: number | null }
  | {
      readonly kind: 'done';
      readonly outcome: BusinessOutcome;
      readonly delivered: number;
      readonly httpStatus: number | null;
      readonly elapsedMs: number;
      readonly ruleId: string | null;
    };

export function lanes(run: LiveRunView | null, stepNo = 1): Readonly<Record<ControlId, LaneState>> {
  const step = run?.steps.find((candidate) => candidate.stepNo === stepNo);
  const result = {} as Record<ControlId, LaneState>;
  for (const control of CONTROL_ORDER) {
    const layer = step?.layers[control];
    const stream = step?.streams?.[control];
    if (layer) {
      result[control] = {
        kind: 'done',
        outcome: layer.outcome,
        delivered: layer.deliveredItems,
        httpStatus: layer.httpStatus,
        elapsedMs: layer.elapsedMs,
        ruleId: layer.ruleId ?? null,
      };
    } else if (stream) {
      result[control] = { kind: 'streaming', delivered: stream.delivered, total: stream.total };
    } else {
      result[control] = { kind: 'waiting' };
    }
  }
  return result;
}

/** The engine's decision as its analysis events tell it: the applied action and when, timed from the request. */
export interface EngineDecision {
  readonly action: string;
  readonly atMs: number | null;
  readonly riskScore: number | null;
  readonly confidence: number | null;
}

export function decision(stages: readonly AnalysisStage[]): EngineDecision | null {
  const applied = stages.find((stage) => stage.type === 'DECISION_APPLIED' && stage.action);
  if (!applied?.action) {
    return null;
  }
  const candidate = [...stages]
    .reverse()
    .find((stage) => (stage.type === 'LAYER2_COMPLETE' || stage.type === 'LAYER1_COMPLETE') && stage.action);
  return {
    action: applied.action,
    atMs: applied.atMs,
    riskScore: candidate?.riskScore ?? null,
    confidence: candidate?.confidence ?? null,
  };
}

/**
 * The conclusion of a scene, from Contexa's lane and the engine's decision.
 * - cut: the engine stopped the stream part-way (only from its own marker, outcome CUT)
 * - stopped: the request was refused before any data left
 * - leakedThenLocked: the data left while the engine decided, and the decision now holds the account
 * - missed: the engine let the attack through
 * - completed / halted / checked: the real owner's work got through, was stopped, or is held for a check
 * - unresolved: a technical fault, no decision
 */
export type Conclusion =
  | { readonly kind: 'cut'; readonly delivered: number; readonly total: number; readonly atMs: number | null }
  | { readonly kind: 'stopped'; readonly delivered: number }
  | { readonly kind: 'leakedThenLocked'; readonly delivered: number; readonly action: string }
  | { readonly kind: 'missed'; readonly delivered: number }
  | { readonly kind: 'completed'; readonly delivered: number }
  | { readonly kind: 'halted' }
  | { readonly kind: 'checked' }
  | { readonly kind: 'unresolved' };

const HOLDING = new Set(['BLOCK', 'CHALLENGE', 'ESCALATE']);

export function conclusion(
  role: Role,
  contexa: LaneState,
  engine: EngineDecision | null,
  total: number,
): Conclusion | null {
  if (contexa.kind !== 'done') {
    return null;
  }
  switch (contexa.outcome) {
    case 'CUT':
      return { kind: 'cut', delivered: contexa.delivered, total, atMs: engine?.atMs ?? null };
    case 'STOPPED':
      return role === 'attacker' ? { kind: 'stopped', delivered: contexa.delivered } : { kind: 'halted' };
    case 'HELD':
      return role === 'attacker' ? { kind: 'stopped', delivered: contexa.delivered } : { kind: 'checked' };
    case 'BROKEN':
      if (role === 'owner') {
        return { kind: 'halted' };
      }
      return engine && HOLDING.has(engine.action)
        ? { kind: 'leakedThenLocked', delivered: contexa.delivered, action: engine.action }
        : { kind: 'missed', delivered: contexa.delivered };
    case 'UNRESOLVED':
      return { kind: 'unresolved' };
    default:
      if (role === 'owner') {
        return { kind: 'completed', delivered: contexa.delivered };
      }
      return engine && HOLDING.has(engine.action)
        ? { kind: 'leakedThenLocked', delivered: contexa.delivered, action: engine.action }
        : { kind: 'missed', delivered: contexa.delivered };
  }
}

/**
 * Data that has left through the existing security of the first scene (perimeter security and the permission check):
 * the same documents go out at both, so the larger count is how much of them has left.
 */
export function leakedThroughExisting(state: Readonly<Record<ControlId, LaneState>>): number {
  return Math.max(deliveredOf(state.A), deliveredOf(state.B));
}

export function deliveredOf(lane: LaneState): number {
  return lane.kind === 'waiting' ? 0 : lane.delivered;
}

/** What the attacker's second try met at Contexa: the engine's hold on the account, or nothing that held it. */
export type RetryAnswer = 'BLOCK' | 'CHALLENGE' | 'PASSED' | 'OTHER';

/**
 * Read from the rule Contexa recorded for the answer (H-06), never guessed from the HTTP status: a 403 of the
 * application's own permission check is not a block of the account.
 */
export function retryAnswer(lane: LaneState): RetryAnswer | null {
  if (lane.kind !== 'done') {
    return null;
  }
  if (lane.outcome === 'DELIVERED') {
    return 'PASSED';
  }
  switch (lane.ruleId) {
    case 'ACCOUNT_BLOCKED':
      return 'BLOCK';
    case 'MFA_CHALLENGE_REQUIRED':
    case 'ZERO_TRUST_CHALLENGE':
      return 'CHALLENGE';
    default:
      return 'OTHER';
  }
}
