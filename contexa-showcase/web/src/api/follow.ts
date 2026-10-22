import { useQuery } from '@tanstack/react-query';
import { getJson, HttpError } from './http';

/** The latest block that was actually released (FU-4): the run and step whose stored anatomy holds the release. */
export interface LatestRelease {
  readonly runId: string;
  readonly stepNo: number;
  readonly scenarioKey: string;
  /** The decision forced on control D for the run (development only); null for the engine's own judgment. */
  readonly forcedAction: string | null;
  readonly approvedAt: string | null;
}

/** The engine's record of the block as its administrator API returned it to the portal. */
export interface StoredBlockRecord {
  readonly status: string | null;
  readonly reasoning: string | null;
  readonly mfaVerified: boolean | null;
  readonly unblockReason: string | null;
}

/** A step's stored release (run_release) as the anatomy carries it, times in UTC. */
export interface StoredRelease {
  readonly released: boolean;
  readonly reason: string | null;
  readonly blocked_at: string | null;
  readonly code_requested_at: string | null;
  readonly verified_at: string | null;
  readonly requested_at: string | null;
  readonly approved_at: string | null;
  readonly reissue_sent_at: string | null;
  readonly reissue_status: number | null;
  readonly reissue_outcome: string | null;
  readonly reissue_delivered: number | null;
  readonly block_record: StoredBlockRecord | null;
}

/** The latest released block; null when the demo has none yet. */
export function useLatestRelease() {
  return useQuery({
    queryKey: ['follow-release'],
    queryFn: async () => {
      try {
        return await getJson<LatestRelease>('/api/follow/release');
      } catch (error) {
        if (error instanceof HttpError && error.status === 404) {
          return null;
        }
        throw error;
      }
    },
    staleTime: 60_000,
    retry: false,
  });
}
