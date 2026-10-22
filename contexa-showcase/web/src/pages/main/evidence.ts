import type { useTranslation } from 'react-i18next';
import { useAnatomy, useReceived } from '../../api/anatomy';
import { useBenchmark } from '../../api/benchmark';
import { useJourney } from '../../api/journey';
import { useRunStepResults } from '../../api/lab';
import { useRunFacts, useRunQuality, type PromptFact, type RunFacts } from '../../api/promptQuality';
import { useVisitor } from '../../api/queries';
import { count } from '../../journey/format';
import { MAIN_CASES } from './mainCases';
import type { DecisionAnatomyView } from '../../api/anatomy';

/**
 * The run group 3 lays open (설계서 3-1 ~ 3-3): the visitor's own latest finished attack run, or, for a visitor who did
 * not send it, the latest run of the same case in the current measurement, named as such by its source badge. Every
 * value of the three screens is that run's stored record.
 */
export function useEvidenceRun(caseKey: string = MAIN_CASES.attacker) {
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const own = [...(journey.data?.runs ?? [])]
    .reverse()
    .find((run) => run.scenarioKey === caseKey && !run.lab && run.status === 'COMPLETED');
  // The measurement is read anyway (cached for the screens of group 5); its run stands in only without an own run.
  const benchmark = useBenchmark(null);
  const measured = own
    ? null
    : (benchmark.data?.cases.find((found) => found.key === caseKey)?.runIds.at(-1) ?? null);
  const runId = own?.runId ?? measured;
  const anatomy = useAnatomy(runId, 1);
  const received = useReceived(runId, 1);
  const facts = useRunFacts(runId, 1);
  const quality = useRunQuality(runId, 1);
  const [result] = useRunStepResults(runId, 1);
  return {
    pending: journey.isPending || (!own && benchmark.isPending) || (runId !== null && anatomy.isPending),
    runId,
    /** The run is the visitor's own; otherwise a run of the measurement. */
    own: own !== undefined,
    /** The visitor's own run as the journey lists it (every approach's result); null for a measured run. */
    line: own ?? null,
    /** Every approach's result of the run: the visitor's own, else as the measurement scored it. */
    results:
      own?.business ??
      (runId
        ? (benchmark.data?.cases.find((found) => found.key === caseKey)?.runResults?.[runId] ?? null)
        : null),
    anatomy: anatomy.data ?? null,
    received: received.data ?? null,
    facts: facts.data ?? null,
    quality: quality.data ?? null,
    contexa: result?.layers.find((layer) => layer.control === 'D') ?? null,
  };
}

/** A fact line of the sealed prompt by its label, in the block it belongs to; null when the prompt has none. */
export function factLine(facts: RunFacts | null, label: string): PromptFact | null {
  for (const block of facts?.blocks ?? []) {
    const found = block.facts.find((fact) => fact.label === label);
    if (found) {
      return found;
    }
  }
  return null;
}

/** A fact line of the sealed prompt by the fact ID a reason code cites (F4); null when the prompt has none. */
export function factById(facts: RunFacts | null, factId: string): PromptFact | null {
  for (const block of facts?.blocks ?? []) {
    const found = block.facts.find((fact) => fact.factId === factId);
    if (found) {
      return found;
    }
  }
  return null;
}

/** A fact line as the prompt holds it: "F4 PolicySatisfied: no — no approval for GB-500". */
export function lineText(fact: PromptFact): string {
  return `${fact.factId ? `${fact.factId} ` : ''}${fact.label}: ${fact.value}`;
}

/** The first and last characters of a SHA-256, as the seal line writes it. */
export function shortHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 6)}…${hash.slice(-4)}` : hash;
}

/**
 * The model calls of a decision as 3-1 and 3-3 state them: the model, the number of calls, every call's tokens and the
 * model time, as the server summed them (a response check that asks again makes a second call).
 */
export function modelSummary(anatomy: DecisionAnatomyView): {
  readonly model: string | null;
  readonly calls: number;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly ms: number | null;
} {
  const calls = anatomy.interpretation.calls;
  const last = calls[calls.length - 1] ?? null;
  return {
    model: last?.model ?? null,
    calls: calls.length,
    promptTokens: anatomy.interpretation.promptTokens ?? 0,
    completionTokens: anatomy.interpretation.completionTokens ?? 0,
    ms: anatomy.interpretation.timings.llmLatencyMs ?? last?.elapsedMs ?? null,
  };
}

type T = ReturnType<typeof useTranslation>['t'];

/** The engine's window of the work profile in words: "7d" as seven days, anything else as the engine wrote it. */
function windowWords(t: T, window: string): string {
  const days = /^(\d+)d$/.exec(window);
  return days?.[1] ? t('main.window.days', { count: Number(days[1]) }) : window;
}

/**
 * The learned requests a decision compared, as every screen names them (V-08, review 2026-10-21): the learned
 * requests before the run and the recent ones of the work profile's window the request was compared with, both read
 * from the run's figures. Null when the record does not hold the recent ones.
 */
export function learnedCompared(
  t: T,
  figures: Pick<
    DecisionAnatomyView['figures'],
    'workProfileWindow' | 'workProfileObservations' | 'baselineBefore'
  >,
  language: string,
): string | null {
  const recent = figures.workProfileObservations;
  if (recent === null || figures.workProfileWindow === null) {
    return null;
  }
  const window = windowWords(t, figures.workProfileWindow);
  return figures.baselineBefore === null
    ? t('main.learned.recent', { count: recent, recent: count(recent, language), window })
    : t('main.learned.compared', {
        count: figures.baselineBefore,
        total: count(figures.baselineBefore, language),
        recent: count(recent, language),
        window,
      });
}

/** The inspector's checks the screens name, in the one order they list them (P-39): the seal first. */
const CHECK_ORDER = ['SEAL_INTEGRITY', 'FACT_ACCURACY', 'DECISION_FACT_MATCH', 'REASON_MATCH'];

/** The inspector's checks in that order, the first `limit` of them; checks the screens do not name are left out. */
export function inOrder<C extends { readonly code: string }>(
  checks: readonly C[],
  limit: number = CHECK_ORDER.length,
): readonly C[] {
  return CHECK_ORDER.slice(0, limit)
    .map((code) => checks.find((check) => check.code === code))
    .filter((check): check is C => check !== undefined);
}

/**
 * How much a run added to the usual pattern beside the arrow of its two counts: the growth of that count, and the
 * documents it added only when the counts are not known.
 */
export function learnedAdded(before: number | null, after: number | null, documents: number): number {
  return before !== null && after !== null ? Math.max(0, after - before) : documents;
}
