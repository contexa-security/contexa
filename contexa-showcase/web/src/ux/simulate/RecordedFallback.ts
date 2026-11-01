import { useHook } from '../../api/hook';
import { useMeasuredCase } from '../../api/measured';
import type { PersonKey } from './person';

/**
 * A stored real run of the same scenario, where a refused or failed live run leads instead of a dead end (deck p.20,
 * ST-3 · ST-4 · ST-16): the published recorded run of the account takeover pair, else the measurement's middle run.
 */
export function useRecordedRun(key: PersonKey): string | null {
  const hook = useHook();
  const measured = useMeasuredCase(key === 'S16' ? key : null);
  if (key === 'S13') {
    return hook.data?.attacker.runId ?? null;
  }
  if (key === 'S13T') {
    return hook.data?.owner.runId ?? null;
  }
  return measured.data?.middleRun ?? null;
}
