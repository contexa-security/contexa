import { useJourney, type RecapLine } from '../../api/journey';
import { useLiveConfig, useVisitor } from '../../api/queries';
import { latestOwnRun } from './latestRun';
import { sortAgentKeys } from './agent';
import { PERSON, PERSON_KEYS, type PersonKey } from './person';

/**
 * The visitor's own runs of a group's scenarios, read from the journey once the visitor cookie exists (the portal
 * answers 401 before it). The progress is the business count "scenarios run in this group n / total" (기획안 F-9,
 * DEC-3).
 */
export function useGroupRuns(keys: readonly string[]) {
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const runs = journey.data?.runs;
  const latest = (key: string): RecapLine | null => latestOwnRun(runs, key);
  return {
    ready: journey.isSuccess && keys.length > 0,
    visitorReady: visitor.isSuccess,
    done: keys.filter((key) => latest(key) !== null).length,
    total: keys.length,
    latest,
    predictions: journey.data?.predictions ?? [],
  };
}

export function usePersonRuns() {
  const runs = useGroupRuns(PERSON_KEYS);
  return {
    ...runs,
    latest: (key: PersonKey) => runs.latest(key),
    /** The visitor's call before the run, scored by the server against its latest run (DEC-22). */
    prediction: (key: PersonKey) =>
      runs.predictions.find(
        (prediction) => prediction.experience === PERSON[key].experience && prediction.caseKey === key,
      ) ?? null,
  };
}

/** The agent group's runs: the cases the portal lists for visitors (the delegation-change case is the simulator's). */
export function useAgentRuns() {
  const config = useLiveConfig();
  return useGroupRuns(sortAgentKeys((config.data?.agentCases ?? []).map((item) => item.key)));
}
