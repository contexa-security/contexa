import { skipToken, useQuery } from '@tanstack/react-query';
import type { BenchmarkRate } from './benchmark';
import { getJson, HttpError } from './http';
import type { ReasonCode } from './types';

/**
 * The prompt trust views of the portal (docs/showcase/화면설계-프롬프트신뢰-보강안.md 5, plan W7-13): the facts of the
 * sealed v20 prompt of a step with their source grades, the quality of that step (seal, latest inspection, reason
 * codes, the ribbon's counts), what a lab run's changed condition changed in the AI input, and the prompt-quality
 * measurement of a batch. Every value is the server's; nothing is counted here.
 */

/** Where a fact of the v20 prompt comes from, as the line states it (the dictionary's five source grades). */
export type FactSource = 'HOST' | 'LEARNED' | 'COMPUTED' | 'INFERRED' | 'UNTRUSTED';

/** The v20 blocks that hold facts (the rules are the system text, not facts). */
export type FactBlock =
  | 'REQUEST'
  | 'SESSION'
  | 'USER_BASELINE'
  | 'DECISION_FACTS'
  | 'UNKNOWN'
  | 'PAST_RECORDS'
  | 'UNTRUSTED_TEXT'
  | 'SECOND_PASS';

export interface PromptFact {
  /** The line of the user prompt the fact is drawn on, counted from 1. */
  readonly line: number;
  /** The fact ID the line starts with (F3 and so on); null for a line without one. */
  readonly factId: string | null;
  readonly label: string;
  readonly value: string;
  /** The source grade of the line; null when the line states none. */
  readonly source: FactSource | null;
  /** The source grades the dictionary entry of the line allows, in the grade order. */
  readonly grades: readonly string[];
}

export interface FactBlockView {
  readonly block: FactBlock;
  readonly facts: readonly PromptFact[];
}

/** The prompt bundle the decision used, as its seal names it. */
export interface BundleDescriptor {
  readonly version: string | null;
  readonly hash: string | null;
  /** How the bundle was selected: the setting, the registry or the shadow run. */
  readonly selectionSource: string | null;
  readonly layout: string | null;
}

/** Why a step's facts or quality are not there: no such step, not sealed yet, or control D not reachable. */
export type ViewReason = 'NO_STEP' | 'NOT_SEALED' | 'NO_ENGINE';

export interface RunFacts {
  readonly runId: string;
  readonly stepNo: number;
  /** False when the step has no sealed v20 prompt to read; `reason` says why. */
  readonly available: boolean;
  readonly reason: ViewReason | null;
  readonly bundle: BundleDescriptor | null;
  readonly blocks: readonly FactBlockView[];
}

export interface InspectionMismatch {
  readonly block: string | null;
  readonly entry: string | null;
  readonly factId: string | null;
  readonly line: number | null;
  readonly expected: string | null;
  readonly actual: string | null;
  readonly reason: string | null;
}

/** One check of the official inspector v2 with its counts and the lines it found wrong. */
export interface InspectionCheck {
  readonly code: string;
  readonly matched: number;
  readonly mismatched: number;
  readonly unverifiable: number;
  readonly mismatches: readonly InspectionMismatch[];
}

export interface Inspection {
  readonly verdict: string;
  readonly inspectorVersion: string | null;
  readonly inspectedAt: string | null;
  readonly checks: readonly InspectionCheck[];
}

export interface Seal {
  readonly packageId: string;
  readonly packageHash: string | null;
  readonly capturedAt: string | null;
}

/**
 * The quality ribbon's counts, as the server counted them from the facts and the inspection; the two counts the
 * inspection gives are null while the seal has no inspection yet.
 */
export interface QualityRibbonView {
  readonly facts: number;
  readonly withSource: number;
  readonly factAccuracy: { readonly matched: number; readonly total: number } | null;
  readonly contradictions: number | null;
  readonly unknown: number;
}

export interface RunQuality {
  readonly available: boolean;
  readonly reason: ViewReason | null;
  readonly bundle: BundleDescriptor | null;
  readonly seal: Seal | null;
  /** The latest stored inspection; null before the first one. */
  readonly inspection: Inspection | null;
  /** The reason codes of the sealed decision, each with the fact ID it cites. */
  readonly reasonCodes: readonly ReasonCode[];
  readonly ribbon: QualityRibbonView | null;
}

/** A line the changed condition changed: the values of the label before and after. */
export interface DeltaLine {
  readonly label: string;
  readonly before: readonly string[];
  readonly after: readonly string[];
}

export interface DeltaStep {
  readonly stepNo: number;
  readonly changed: readonly DeltaLine[];
  /** The labels the condition is expected to change. */
  readonly expected: readonly string[];
  /** The changed labels the condition was not expected to change. */
  readonly unexpected: readonly string[];
  /** Whether the changed line states the requested value; null when no value is checked. */
  readonly valueMatches: boolean | null;
  /** The delivery check of the step, as the server decided it. */
  readonly passed: boolean;
  /**
   * Why the step was not compared: the variant has no such step; neither run sealed it, or only one did
   * after an earlier request was decided differently (both left out of the runs' check); or only one did
   * after the same decisions (a difference). Null if it was compared.
   */
  readonly notCompared:
    'NO_VARIANT_STEP' | 'NOT_SEALED' | 'NOT_SEALED_ONE_SIDE' | 'NOT_SEALED_AFTER_DIFFERENT_DECISION' | null;
  /** How many lines of the AI input the change left as they were; absent when the server does not say. */
  readonly unchangedLines?: number | null;
  /**
   * What the request's work does not look up for the changed condition (a kind of company record, or the
   * ticket the requester named), so its value cannot reach the AI input; null or absent when it does.
   */
  readonly notLookedUp?: 'APPROVAL' | 'ON_CALL' | 'TICKET' | 'CLAIMED_TICKET' | null;
}

/** Why a lab run has no delta: run as designed, several conditions changed, not finished, no base, no control D. */
export type DeltaReason = 'DESIGNED' | 'SEVERAL_CONDITIONS' | 'NOT_COMPLETED' | 'NO_BASE' | 'NO_ENGINE';

export interface LabDelta {
  readonly runId: string;
  readonly baseRunId: string | null;
  readonly condition: string | null;
  readonly value: string | null;
  readonly available: boolean;
  readonly reason: DeltaReason | null;
  readonly steps: readonly DeltaStep[];
}

/** One side of the other-bundle comparison: the run and step, the bundle it used, and its texts as sent. */
export interface BundleSide {
  readonly runId: string;
  readonly stepNo: number;
  readonly bundle: {
    readonly version: string | null;
    readonly hash: string | null;
    readonly selectionSource: string | null;
  };
  readonly userPrompt: string | null;
  /** How many lines the system text had, as the server counted them. */
  readonly systemPromptLines: number | null;
}

/** Why there is no comparison: no measured run of the case under the other bundle, not sealed, no control D, no step. */
export type OtherBundleReason = 'NO_OTHER_BUNDLE_RUN' | 'NOT_SEALED' | 'NO_ENGINE' | 'NO_STEP';

/** This step and the measured run of the same case and conditions under the other bundle (not the same request). */
export interface OtherBundleView {
  readonly available: boolean;
  readonly reason: OtherBundleReason | null;
  readonly current: BundleSide | null;
  readonly other: BundleSide | null;
}

/** The prompt-quality measurement of a published batch (the benchmark's prompt-quality view). */
export interface PromptQualityView {
  readonly measuredAt: string;
  readonly setting: string | null;
  readonly batch: string | null;
  readonly protocol: string | null;
  readonly delivery: BenchmarkRate;
  readonly reaction: {
    readonly direction: BenchmarkRate;
    readonly minimumKept: BenchmarkRate;
    readonly consistency: BenchmarkRate;
  };
  readonly invariance: {
    readonly firstStepFacts: BenchmarkRate;
    readonly decisions: BenchmarkRate;
    /** How many repeated decisions came out differently, as the server counted them. */
    readonly decisionChanges: number;
  };
  /** The injected variants whose decision changed, and those decided as before the injection. */
  readonly injection: { readonly changed: number; readonly unchanged: BenchmarkRate };
  readonly accuracy: BenchmarkRate;
  readonly consistency: BenchmarkRate;
  readonly reasonMatch: BenchmarkRate;
}

/**
 * A step's seal and inspection come shortly after its decision, and a lab run's delta after the run ends: a view the
 * server says is coming (not sealed, not inspected, not finished) is read again a few times, then left as it is. A
 * view that cannot come (no step, no base, run as designed) is not read again.
 */
const PENDING_TRIES = 12;
const PENDING_INTERVAL_MS = 5_000;
const COMING: ReadonlySet<string> = new Set(['NOT_SEALED', 'NOT_COMPLETED']);

interface Coming {
  readonly available: boolean;
  readonly reason: string | null;
  readonly ribbon?: { readonly factAccuracy: unknown } | null;
}

function againWhileComing(query: {
  readonly state: { readonly data: Coming | undefined; readonly dataUpdateCount: number };
}): number | false {
  const data = query.state.data;
  const coming =
    data !== undefined &&
    ((!data.available && data.reason !== null && COMING.has(data.reason)) || data.ribbon?.factAccuracy === null);
  return coming && query.state.dataUpdateCount < PENDING_TRIES ? PENDING_INTERVAL_MS : false;
}

/** The facts of a step's sealed prompt, by block. */
export function useRunFacts(runId: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['run-facts', runId, stepNo],
    queryFn: runId
      ? () => getJson<RunFacts>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/facts`)
      : skipToken,
    staleTime: 60_000,
    retry: false,
    refetchInterval: againWhileComing,
  });
}

/** The quality of a step: bundle, seal, latest inspection, reason codes and the ribbon's counts. */
export function useRunQuality(runId: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['run-quality', runId, stepNo],
    queryFn: runId
      ? () => getJson<RunQuality>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/quality`)
      : skipToken,
    staleTime: 60_000,
    retry: false,
    refetchInterval: againWhileComing,
  });
}

/** What a lab run's changed condition changed in the AI input, compared with its base run on the server. */
export function useLabDelta(runId: string | null) {
  return useQuery({
    queryKey: ['lab-delta', runId],
    queryFn: runId ? () => getJson<LabDelta>(`/api/lab/runs/${encodeURIComponent(runId)}/delta`) : skipToken,
    staleTime: 60_000,
    retry: false,
    refetchInterval: againWhileComing,
  });
}

/** The same case under the other bundle, for a step of a run; read once the screen has the run. */
export function useOtherBundle(runId: string | null, stepNo: number) {
  return useQuery({
    queryKey: ['other-bundle', runId, stepNo],
    queryFn: runId
      ? () => getJson<OtherBundleView>(`/api/runs/${encodeURIComponent(runId)}/steps/${stepNo}/other-bundle`)
      : skipToken,
    staleTime: 60_000,
    retry: false,
    refetchInterval: againWhileComing,
  });
}

/** The prompt-quality measurement of a setting, the latest batch when none is named; 404 until one is published. */
export function usePromptQuality(setting: string | null) {
  return useQuery({
    queryKey: ['prompt-quality', setting],
    queryFn: () =>
      getJson<PromptQualityView>(
        `/api/benchmark/prompt-quality${setting ? `?setting=${encodeURIComponent(setting)}` : ''}`,
      ),
    staleTime: 60_000,
    retry: false,
  });
}

/** Whether a failed read means the server has no published measurement yet (404). */
export function notPublished(error: unknown): boolean {
  return error instanceof HttpError && error.status === 404;
}
