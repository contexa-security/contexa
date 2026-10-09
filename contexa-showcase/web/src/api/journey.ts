import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getJson, postJson } from './http';

/**
 * The visitor's journey (portal JourneyViews): where the visitor is, kept on the server so a reload or another tab
 * returns to the same place; the visitor's own runs as "what you did"; and the visitor's calls scored by the server.
 */
export type Route = 'DEFAULT' | 'INTRO';
export type EngineCall = 'ALLOW' | 'CHALLENGE' | 'ESCALATE' | 'BLOCK';
export type ExistingCall = 'ALL' | 'SOME' | 'NONE';
export type NumberRuleCall = 'STOP' | 'PASS';

export interface JourneyState {
  readonly route: Route;
  /** 0 before the first act, then 1 to 4. */
  readonly act: number;
  readonly step: string;
  /** The numbers (1 to 6) of the differences the visitor has seen. */
  readonly differences: readonly number[];
  readonly predictions: Readonly<Record<string, Readonly<Record<string, string>>>>;
  readonly updatedAt: string;
}

export interface RecapLine {
  readonly runId: string;
  /** When the run started, as recorded. */
  readonly startedAt?: string;
  readonly scenarioKey: string;
  readonly classification: string | null;
  readonly status: string;
  readonly lab: boolean;
  /** Every approach's business result as recorded, by control. */
  readonly business: Readonly<Record<string, string>>;
  readonly engineAction: string | null;
  readonly exposedItems: number;
  /** Whether Contexa's result is right by the case's ground truth; null when it is neither. */
  readonly correct: boolean | null;
  /** The items the case's first step asks for, as its definition says; null without a count. */
  readonly requestedItems: number | null;
  /** The number of requests the case sends, as its definition says; 0 when unknown. */
  readonly steps: number;
}

export interface Prediction {
  readonly experience: 'E1' | 'E2';
  readonly engine?: EngineCall | null;
  readonly existing?: ExistingCall | null;
  readonly numberRule?: NumberRuleCall | null;
}

export interface PredictionScore {
  readonly experience: string;
  readonly caseKey: string;
  readonly call: Prediction;
  readonly engineRight: boolean | null;
  /** How many of the four existing approaches stopped the visitor's latest run of the case; null before it. */
  readonly existingActual: ExistingCall | null;
  readonly numberRuleActual: NumberRuleCall | null;
  readonly runId: string | null;
}

export interface JourneyView {
  readonly state: JourneyState;
  readonly runs: readonly RecapLine[];
  readonly predictions: readonly PredictionScore[];
}

export interface JourneyUpdate {
  readonly route?: Route;
  readonly act?: number;
  readonly step?: string;
  /** A difference the visitor has now seen (1 to 6). */
  readonly difference?: number;
  readonly prediction?: Prediction;
}

/** A quiz question as the visitor sees it; the answer stays on the server. */
export interface QuizQuestion {
  readonly id: 'Q1' | 'Q2' | 'Q3';
  readonly options: readonly string[];
}

export interface QuizAnswer {
  readonly question: string;
  readonly answer: string;
  readonly right: boolean;
  readonly correct: string;
  /** The difference (1 to 6) whose screen a wrong answer leads back to. */
  readonly revisit: number;
}

export interface QuizResult {
  readonly answers: readonly QuizAnswer[];
  readonly right: number;
  readonly total: number;
  /** Whether these answers entered the anonymous counts (a visitor's first answers only). */
  readonly counted: boolean;
}

/** The values of the card at the end of an act; the sentence lives in the dictionary. */
export interface ActEnd {
  readonly act: number;
  readonly caseKey: string;
  readonly source: 'VISITOR_RUN' | 'MEASUREMENT' | 'NONE';
  readonly runId: string | null;
  readonly values: Readonly<Record<string, unknown>>;
}

/** The anonymous daily counts still kept (ADR-35). */
export interface TallySummary {
  readonly from: string | null;
  readonly to: string | null;
  readonly quiz: Readonly<Record<string, { readonly right: number; readonly total: number }>>;
  readonly actReached: Readonly<Record<string, number>>;
}

export function useQuizQuestions() {
  return useQuery({
    queryKey: ['quiz'],
    queryFn: () => getJson<readonly QuizQuestion[]>('/api/quiz'),
    staleTime: Infinity,
  });
}

export async function answerQuiz(answers: Readonly<Record<string, string>>): Promise<QuizResult | null> {
  const result = await postJson<QuizResult>('/api/quiz', { answers });
  return result.status === 200 ? result.body : null;
}

export function useActEnd(act: number, enabled: boolean) {
  return useQuery({
    queryKey: ['act-end', act],
    queryFn: () => getJson<ActEnd>(`/api/journey/act-end?act=${act}`),
    enabled,
    retry: false,
  });
}

export function useTally() {
  return useQuery({
    queryKey: ['tally'],
    queryFn: () => getJson<TallySummary>('/api/tally'),
    staleTime: 60_000,
  });
}

/** The journey of the visitor of the cookie; read once the visitor cookie exists (useVisitor). */
export function useJourney(enabled = true) {
  return useQuery({
    queryKey: ['journey'],
    queryFn: () => getJson<JourneyView>('/api/journey'),
    enabled,
    retry: false,
  });
}

/** Sends a change of the journey and keeps the answer as the current journey. */
export function useJourneyUpdate() {
  const client = useQueryClient();
  return async (update: JourneyUpdate): Promise<JourneyView | null> => {
    const result = await postJson<JourneyView>('/api/journey', update);
    if (result.status === 200 && result.body !== null) {
      client.setQueryData(['journey'], result.body);
      return result.body;
    }
    return null;
  };
}
