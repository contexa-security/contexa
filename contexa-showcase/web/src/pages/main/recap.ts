import { AGENT_CASE } from '../../api/agentCase';
import type { RecapLine } from '../../api/journey';
import { MAIN_CASES } from './mainCases';

/** Contexa's business results that kept data in, wholly or after some left. */
const STOPPED_RESULTS: ReadonlySet<string> = new Set(['STOPPED', 'PARTLY_STOPPED']);

/** The judgments that keep the data in: a stop, an extra check or a hold for the administrator. */
const KEPT_IN = new Set(['BLOCK', 'ESCALATE', 'CHALLENGE']);

/** The existing security, whose results the insider's line names. */
const EXISTING = ['A', 'B', 'C1', 'C2'];

/** The owner's results that let the work through: at once, or after an extra check. */
const WORK_DONE = new Set(['PASSED', 'PASSED_AFTER_CHECK']);

/** The visitor's latest own run of a case on the main flow (lab runs are the lab's). */
export function latestRun(
  runs: readonly RecapLine[] | undefined,
  caseKey: string | readonly string[],
): RecapLine | null {
  const keys = typeof caseKey === 'string' ? [caseKey] : caseKey;
  const own = (runs ?? []).filter((run) => keys.includes(run.scenarioKey) && !run.lab);
  return own.length > 0 ? (own[own.length - 1] ?? null) : null;
}

/** The line of what the visitor just saw: its key, a count, and the keys of the words it names in its places. */
export interface PastLine {
  readonly key: string;
  readonly n?: number;
  readonly parts?: Readonly<Record<string, string>>;
}

/** The lane a next-chooser follows: the case the visitor just finished. */
export type RecapLane = 'attack' | 'normal' | 'insider' | 'agent';

/**
 * What the visitor just saw, as one line of the visitor's own runs (설계서: 지난 주제 한 줄, moved from the group
 * covers to the next-choosers, docs/showcase 첫화면-선택형-체험-구현계획 1절): it names a result only when the visitor's
 * run recorded it, and otherwise says what the case was about, never a result it did not have. The keys are the
 * dictionary's `cover.{group}.past*` lines the covers used.
 */
export function pastLine(
  lane: RecapLane,
  runs: readonly RecapLine[] | undefined,
  agentCases: readonly string[] = [AGENT_CASE],
): PastLine {
  if (lane === 'attack') {
    const attack = latestRun(runs, MAIN_CASES.attacker);
    if (!attack || attack.engineAction === null) {
      return { key: 'cover.3.past.none' };
    }
    if (KEPT_IN.has(attack.engineAction) && attack.exposedItems === 0) {
      return { key: `cover.3.past.${attack.engineAction}` };
    }
    return { key: 'cover.3.past.through' };
  }
  if (lane === 'normal') {
    const attack = latestRun(runs, MAIN_CASES.attacker);
    const normal = latestRun(runs, MAIN_CASES.owner);
    const owner = normal?.business['D'] ?? '';
    const action = attack?.engineAction ?? null;
    // P-05: the split names what Contexa did on each side, as each run recorded it.
    return action !== null && KEPT_IN.has(action) && attack?.exposedItems === 0 && WORK_DONE.has(owner)
      ? {
          key: 'cover.5.past.split',
          parts: { attack: `cover.5.past.attack.${action}`, owner: `cover.5.past.owner.${owner}` },
        }
      : { key: 'cover.5.past.none' };
  }
  if (lane === 'insider') {
    // IN-6: the insider's run, named by what the four existing approaches and Contexa did with it.
    const insider = latestRun(runs, MAIN_CASES.insider);
    if (!insider || insider.engineAction === null) {
      return { key: 'cover.6.past.none' };
    }
    // A run of several documents is named by what Contexa did with them, not by its first judgment alone.
    if (!KEPT_IN.has(insider.engineAction) && !STOPPED_RESULTS.has(insider.business['D'] ?? '')) {
      return { key: 'cover.6.past.through' };
    }
    const allPassed = EXISTING.every((control) => insider.business[control] === 'MISSED');
    return { key: allPassed ? 'cover.6.past.held' : 'cover.6.past.heldOnly', n: insider.exposedItems };
  }
  // docs/agent A7-3: the business agent's run, named by what the four existing approaches and Contexa did with it.
  const agent = latestRun(runs, agentCases);
  if (!agent) {
    return { key: 'cover.7.past.none' };
  }
  // A normal work case is not a miss when it goes through; it is a wrong stop when Contexa holds it.
  if (agent.classification === 'NORMAL') {
    return { key: STOPPED_RESULTS.has(agent.business['D'] ?? '') ? 'cover.7.past.normalStopped' : 'cover.7.past.normal' };
  }
  if (!STOPPED_RESULTS.has(agent.business['D'] ?? '')) {
    return { key: 'cover.7.past.through' };
  }
  const allPassed = EXISTING.every((control) => agent.business[control] === 'MISSED');
  return { key: allPassed ? 'cover.7.past.held' : 'cover.7.past.heldOnly' };
}
