import type { LiveRunView, StepResult } from '../api/types';
import type { Selection } from './explore';
import type { BusinessOutcome, ControlId } from './verdict';
import { CONTROL_ORDER } from './verdict';

/**
 * The hands-on experience (docs/showcase/체험우선-설계.md): the visitor sends the same export as the attacker, then as
 * the real owner, then under conditions of their own choosing. Every value here is computed from the live run the
 * visitor just started, or from a stored real run when a live run is not possible.
 */

/** Scene 1: administrator A's stolen password, an export of GB-500 design documents at dawn with no ticket. */
export const ATTACK_SCENE: Selection = { employee: 'adm-a', slot: 'DAWN', items: 4831, ticket: 'NONE', device: 'USUAL' };

/** Scene 2: the same request by the real administrator A, with the GB-500 recovery ticket open. */
export const OWNER_SCENE: Selection = { ...ATTACK_SCENE, ticket: 'MATCH' };

/** What the scene's request deserves: the attack should be stopped, the legitimate work should pass. */
export type Expectation = 'STOP' | 'PASS';

/** One control's answer: what happened to the data, the HTTP status, what was handed over and how long it took. */
export interface Answer {
  readonly outcome: BusinessOutcome;
  readonly httpStatus: number | null;
  readonly deliveredItems: number;
  readonly elapsedMs: number | null;
}

/** A lane waits for its turn, is being sent (the controls are asked one after another), or has its answer. */
export type Lane =
  | { readonly kind: 'waiting' }
  | { readonly kind: 'sending' }
  | { readonly kind: 'done'; readonly answer: Answer };

/** Each control's lane of a live run as it stands; the first control without an answer is the one being sent. */
export function liveLanes(run: LiveRunView | null): Readonly<Record<ControlId, Lane>> {
  const layers = run?.steps[0]?.layers ?? {};
  const sending = run?.status === 'RUNNING';
  let next = true;
  const lanes = {} as Record<ControlId, Lane>;
  for (const control of CONTROL_ORDER) {
    const layer = layers[control];
    if (layer) {
      lanes[control] = {
        kind: 'done',
        answer: {
          outcome: layer.outcome,
          httpStatus: layer.httpStatus,
          deliveredItems: layer.deliveredItems,
          elapsedMs: layer.elapsedMs,
        },
      };
    } else {
      lanes[control] = sending && next ? { kind: 'sending' } : { kind: 'waiting' };
      next = false;
    }
  }
  return lanes;
}

/** The lanes of a stored real run, shown as a record when a live run cannot start. */
export function recordedLanes(result: StepResult): Readonly<Record<ControlId, Lane>> {
  const lanes = {} as Record<ControlId, Lane>;
  for (const control of CONTROL_ORDER) {
    const layer = result.layers.find((candidate) => candidate.control === control);
    lanes[control] = layer
      ? {
          kind: 'done',
          answer: {
            outcome: layer.outcome,
            httpStatus: layer.evidence.httpStatus,
            deliveredItems: layer.evidence.deliveredItems,
            elapsedMs: layer.evidence.responseMs,
          },
        }
      : { kind: 'waiting' };
  }
  return lanes;
}

/** Each control's business outcome once every lane has its answer; null while any is missing. */
export function outcomesOf(lanes: Readonly<Record<ControlId, Lane>>): Readonly<Record<ControlId, BusinessOutcome>> | null {
  const outcomes = {} as Record<ControlId, BusinessOutcome>;
  for (const control of CONTROL_ORDER) {
    const lane = lanes[control];
    if (lane.kind !== 'done') {
      return null;
    }
    outcomes[control] = lane.answer.outcome;
  }
  return outcomes;
}

/**
 * Whether a control's answer was right for the scene. The data held for an identity check counts as passing only when
 * the owner completed the check and the request was served; a technical fault is neither right nor wrong (null).
 */
export function isRight(outcome: BusinessOutcome, expectation: Expectation, servedAfterCheck = false): boolean | null {
  if (outcome === 'UNRESOLVED') {
    return null;
  }
  if (expectation === 'STOP') {
    return outcome !== 'DELIVERED';
  }
  return outcome === 'DELIVERED' || (outcome === 'HELD' && servedAfterCheck);
}

/** A finished scene: each control's outcome, and whether Contexa's check ended with the request served. */
export interface SceneOutcome {
  readonly outcomes: Readonly<Record<ControlId, BusinessOutcome>>;
  readonly servedAfterCheck: boolean;
}

/** The controls that got both scenes right, in layer order. */
export function bothRight(attack: SceneOutcome, owner: SceneOutcome): readonly ControlId[] {
  return CONTROL_ORDER.filter(
    (control) =>
      isRight(attack.outcomes[control], 'STOP') === true &&
      isRight(owner.outcomes[control], 'PASS', control === 'D' && owner.servedAfterCheck) === true,
  );
}

/** The controls whose outcome differs from the previous run under other conditions. */
export function changedFrom(
  current: Readonly<Record<ControlId, BusinessOutcome>>,
  previous: Readonly<Record<ControlId, BusinessOutcome>> | null,
): ReadonlySet<ControlId> {
  if (!previous) {
    return new Set();
  }
  return new Set(CONTROL_ORDER.filter((control) => current[control] !== previous[control]));
}

/** The facts of a request in the order the system window lists them. */
export const FACTS = ['employee', 'slot', 'device', 'ticket', 'items'] as const;

export type Fact = (typeof FACTS)[number];

/** The facts the visitor changed since the previous send. */
export function changedFacts(before: Selection, after: Selection): readonly Fact[] {
  return FACTS.filter((fact) => before[fact] !== after[fact]);
}

/** The i18n key of a lane's answer: what happened to the data, in the words the visitor reads. */
export function answerKey(answer: Answer): string {
  switch (answer.outcome) {
    case 'DELIVERED':
      return 'exp.lane.delivered';
    case 'CUT':
      return 'exp.lane.cut';
    case 'HELD':
      return answer.httpStatus === 423 ? 'exp.lane.review' : 'exp.lane.check';
    case 'UNRESOLVED':
      return 'exp.lane.unresolved';
    default:
      return 'exp.lane.stopped';
  }
}
