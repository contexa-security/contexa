import { skipToken, useQueries, useQuery } from '@tanstack/react-query';
import { getJson, postJson, type PostResult } from './http';
import type { BeforeSend } from './anatomy';
import type { LiveRunView, StepResult } from './types';

/**
 * The lab's choices and the visitor's own lab runs (docs/showcase/데모-재설계.md 5A.1), as the portal returns them
 * (LabController). The choices come from the business database and the designed cases; nothing is added here.
 */
export interface LabConditions {
  readonly employee: string | null;
  readonly timeSlot: string | null;
  readonly place: 'OFFICE' | 'TRAVEL' | 'EXTERNAL' | null;
  readonly device: 'USUAL' | 'NEW' | null;
  readonly operation: string | null;
  readonly target: 'ASSIGNED' | 'UNASSIGNED' | null;
  readonly items: number | null;
  readonly approval: boolean | null;
  readonly ticket: 'NONE' | 'COVERS' | 'OTHER_PROJECT' | null;
  readonly claim: 'NONE' | 'REAL' | 'FAKE' | null;
  readonly onCall: boolean | null;
}

/** A company record the case puts in the business database (ScenarioDefinition.Fact), as the case defines it. */
export interface LabFact {
  readonly kind: string;
  readonly ticketKind: string | null;
  readonly approver: string | null;
  readonly project: string | null;
  readonly purpose: string | null;
  readonly maxItems: number | null;
  readonly status: string | null;
  readonly team: string | null;
  readonly city: string | null;
  readonly country: string | null;
  readonly network: string | null;
}

/** What one request of the case asks for; the rule controls' expected answers are left out (review R-25). */
/** A document named by the case: by project, type and position, or the document the case's N-th fact adds. */
export interface LabDocument {
  readonly project: string | null;
  readonly type: string | null;
  readonly position: number;
  readonly fact: number | null;
}

export interface LabRequest {
  readonly operation: string;
  readonly project: string | null;
  readonly document: LabDocument | null;
  /** Whether the request's project is one the employee works on, from the business database. */
  readonly target: 'ASSIGNED' | 'UNASSIGNED' | null;
  readonly customer: string | null;
  readonly items: number | null;
  readonly claimedTicket: string | null;
  readonly visitorSends: boolean;
}

export interface LabCase {
  readonly key: string;
  readonly version: number;
  readonly title: Readonly<Record<string, string>>;
  /** The ground truth; the lab shows it only after the visitor has sent a judgement (review R-25). */
  readonly classification: string;
  readonly steps: number;
  readonly conditions: LabConditions;
  readonly facts: readonly LabFact[];
  readonly requests: readonly LabRequest[];
}

export interface LabEmployee {
  readonly key: string;
  readonly role: string;
  readonly displayName: string;
  readonly department: string;
  readonly officeNetwork: string;
  readonly assignedProjects: readonly string[];
  readonly customersManaged: number;
  readonly roleAllows: Readonly<Record<string, boolean>>;
}

export interface LabOptions {
  readonly employees: readonly LabEmployee[];
  readonly timeSlots: readonly { readonly slot: string; readonly representativeTime: string }[];
  readonly items: readonly number[];
  readonly operations: readonly string[];
  readonly cases: readonly LabCase[];
  readonly calls: readonly string[];
  readonly assessmentReasons: readonly string[];
}

export interface RecentLabRun {
  readonly runId: string;
  readonly caseKey: string;
  readonly designed: boolean;
  readonly changed: readonly string[];
  readonly conditions: Partial<LabConditions>;
  readonly composedAt: string;
  /** The visitor's judgement sent with the run: NORMAL, ATTACK or UNSURE; null when none was sent. */
  readonly call: string | null;
  /** What the visitor expected of each approach before sending (BLOCK or PASS), when they said. */
  readonly approaches: Readonly<Partial<Record<string, 'BLOCK' | 'PASS'>>>;
}

/** The visitor's call before sending (5A.1 ②): the request as a whole and, optionally, each approach. */
export interface LabPrediction {
  readonly call: 'NORMAL' | 'ATTACK' | 'UNSURE';
  readonly approaches: Readonly<Partial<Record<string, 'BLOCK' | 'PASS'>>>;
}

export interface LabStarted {
  readonly run: LiveRunView;
  readonly designed: boolean;
  readonly changed: readonly string[];
}

/**
 * Starts a lab run: the designed case with only the changed conditions, the visitor's call, and the human check token
 * when the check is on. A refusal comes back with its status and reason ({@link refusalOf} reads it).
 */
export function startLabRun(
  caseKey: string,
  conditions: Partial<LabConditions> | null,
  prediction: LabPrediction,
  turnstileToken: string | null,
): Promise<PostResult<LabStarted & { readonly reason?: string }>> {
  return postJson('/api/lab/runs', { caseKey, conditions, prediction, turnstileToken });
}

/** Other visitors' assessments of the same request, counted after the delay (LabStore.Peers). */
export interface PeerAssessments {
  readonly assessments: number;
  readonly assessors: number;
  readonly verdicts: Readonly<Record<string, number>>;
  readonly reasons: Readonly<Record<string, number>>;
  readonly delayHours: number;
}

export function usePeerAssessments(runId: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['peer-assessments', runId, stepNo],
    queryFn: runId
      ? () =>
          getJson<PeerAssessments>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/peer-assessments`)
      : skipToken,
    staleTime: 60_000,
    retry: false,
  });
}

/** The lab's options query, shared by the screens and by the first-load prefetch (screens.tsx). */
export const labOptionsQuery = {
  queryKey: ['lab-options'],
  queryFn: () => getJson<LabOptions>('/api/lab/options'),
  staleTime: 60_000,
} as const;

export function useLabOptions() {
  return useQuery(labOptionsQuery);
}

/** The comparison before sending a case with changed conditions (POST /api/lab/before): the same reading as a designed case's. */
export function useLabBefore(caseKey: string | null, conditions: Partial<LabConditions> | null, stepNo = 1) {
  return useQuery({
    queryKey: ['lab-before', caseKey, conditions, stepNo],
    queryFn: caseKey
      ? async () => {
          const answer = await postJson<BeforeSend>('/api/lab/before', { caseKey, conditions, step: stepNo });
          if (answer.status !== 200 || answer.body === null) {
            throw new Error(`The comparison before sending answered ${answer.status}`);
          }
          return answer.body;
        }
      : skipToken,
    staleTime: 60_000,
    retry: false,
  });
}

/** One run as the previous-against-this comparison reads it (portal LabVersusController.Side). */
export interface VersusSide {
  readonly runId: string;
  readonly scenarioKey: string;
  /** Every approach's business result, by control (NOT_SCORED for a case without a ground truth). */
  readonly business: Readonly<Record<string, string>>;
  /** How every approach answered (the strongest answer over the run's requests), by control. */
  readonly outcomes: Readonly<Record<string, string>>;
  /** Contexa's first decision in the run; null when it made none. */
  readonly engineAction: string | null;
  readonly exposedItems: number;
}

/** The previous run against this one, compared by the server (lab-3). */
export interface Versus {
  readonly before: VersusSide;
  readonly now: VersusSide;
  readonly changedControls: readonly string[];
  readonly contexaChanged: boolean;
  /** The lab conditions whose value differs between the two runs; null when either run is not a lab run. */
  readonly changedConditions: readonly string[] | null;
  /** What the engine received differently on the first request. */
  readonly inputs: readonly {
    readonly key: string;
    readonly before: string | null;
    readonly now: string | null;
  }[];
}

export function useVersus(runId: string | null, against: string | null) {
  return useQuery({
    queryKey: ['versus', runId, against],
    queryFn:
      runId && against
        ? () =>
            getJson<Versus>(
              `/api/runs/${encodeURIComponent(runId)}/versus?against=${encodeURIComponent(against)}`,
            )
        : skipToken,
    staleTime: Infinity,
    retry: false,
  });
}

export function useRecentLabRuns() {
  return useQuery({
    queryKey: ['lab-recent'],
    queryFn: () => getJson<RecentLabRun[]>('/api/lab/runs/recent'),
  });
}

/** The stored result of a step of any run, every approach side by side. */
export function useStepResult(runId: string | null | undefined, stepNo: number) {
  return useQuery({
    queryKey: ['step-result', runId, stepNo],
    queryFn: runId
      ? () => getJson<StepResult>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/result`)
      : skipToken,
    staleTime: Infinity,
    retry: false,
  });
}

/** Every stored step result of a run, step 1 first; an entry is undefined while it loads. */
export function useRunStepResults(runId: string | null | undefined, steps: number) {
  return useQueries({
    queries: Array.from({ length: runId ? steps : 0 }, (_, index) => ({
      queryKey: ['step-result', runId, index + 1],
      queryFn: () =>
        getJson<StepResult>(`/api/runs/${encodeURIComponent(runId ?? '')}/steps/${index + 1}/result`),
      staleTime: Infinity,
      retry: false,
    })),
  }).map((query) => query.data);
}
