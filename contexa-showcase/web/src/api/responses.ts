import { skipToken, useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/**
 * One approach's stored answer to a step (최종화면-구현계획 EV-1): the request line, when it was sent, the HTTP status,
 * how many items went out, how long the answer took and the start of the answer's body, credentials masked by the
 * portal.
 */
export interface StepResponse {
  readonly control: string;
  readonly method: string;
  readonly path: string;
  readonly sentAt: string | null;
  readonly httpStatus: number | null;
  readonly deliveredItems: number;
  readonly elapsedMs: number | null;
  /** At most the first 2,000 characters of the body, as the run stored it. */
  readonly excerpt: string | null;
}

/** Every approach's answer to the step of a stored run, in the approaches' order. */
export function useStepResponses(runId: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['step-responses', runId, stepNo],
    queryFn: runId
      ? () =>
          getJson<readonly StepResponse[]>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/responses`)
      : skipToken,
    staleTime: Infinity,
    retry: false,
  });
}
