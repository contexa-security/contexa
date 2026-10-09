import { useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/** What a decision does to the user's next requests, as the engine defines it (ZeroTrustAction, read by control D). */
export interface EngineAction {
  readonly httpStatus: number;
  /** How long the decision stays in force; null when it stays until it is released. */
  readonly ttlSeconds: number | null;
}

export type EngineActions = Readonly<
  Partial<Record<'ALLOW' | 'CHALLENGE' | 'ESCALATE' | 'BLOCK', EngineAction>>
>;

export function useEngineActions() {
  return useQuery({
    queryKey: ['engine-actions'],
    queryFn: () => getJson<EngineActions>('/api/engine/actions'),
    staleTime: 10 * 60_000,
    retry: false,
  });
}
