import type { useTranslation } from 'react-i18next';
import type { LabCase } from '../../../api/lab';
import type { LiveRunView } from '../../../api/types';
import { DecisionDetail, type InsideCell } from '../../../components/inside/InsidePanel';
import { analysedCells } from '../../../components/inside/insideCells';
import { count, seconds } from '../../../journey/format';
import { decisionDetail } from '../decision';

/**
 * What a live run's screen reads, shared by the tries and the lab (7.1, 7.6): the nine cells of the inside panel, the
 * word for a decision and what a request of the case asks for. The time bar is in LiveRunBar.
 */

/** The run states during which a run is still going. */
export const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED']);

/** The identity check's stages after which nothing more happens: the follow-up is over. */
export const CHECK_ENDED = new Set(['NO_MAILBOX', 'DONE', 'EXPIRED', 'CANCELLED', 'FAILED', 'ABANDONED']);

/** What a request of the case asks for, as the case defines it. */
export function requestName(
  t: ReturnType<typeof useTranslation>['t'],
  language: string,
  labCase: LabCase,
  stepNo: number,
): string {
  const request = labCase.requests[stepNo - 1];
  if (!request) {
    return '-';
  }
  if (request.document) {
    return t('e1.run.what.DOCUMENT', {
      project: request.document.project ?? request.project ?? '-',
      type: request.document.type ? t(`show.documentType.${request.document.type}`) : '-',
    });
  }
  return t('e1.run.what.EXPORT', {
    project: request.project ?? '-',
    items: request.items === null ? '-' : count(request.items, language),
  });
}

export function verdictKey(verdict: string): string {
  switch (verdict) {
    case 'ALLOW':
      return 'verdict.allow';
    case 'CHALLENGE':
      return 'verdict.verify';
    case 'ESCALATE':
      return 'verdict.review';
    case 'BLOCK':
      return 'verdict.block';
    default:
      return 'verdict.none';
  }
}

/**
 * The nine cells: the first seven from the engine's events and decision, the follow-up from the run's state. A run read
 * back from its records has no live check; `storedCheck` is how its recorded check ended (useStoredCheck).
 */
export function panelCells(
  t: ReturnType<typeof useTranslation>['t'],
  language: string,
  labCase: LabCase,
  view: LiveRunView,
  stages: Parameters<typeof analysedCells>[0],
  decision: Parameters<typeof decisionDetail>[1] | null,
  waitedMs: number | null,
  storedCheck: string | null = null,
): InsideCell[] {
  const checkStage = view.challenge?.stage ?? storedCheck;
  const states = analysedCells(stages, decision !== null);
  const items = labCase.requests[0]?.items ?? null;
  const followUp =
    view.challenge !== null
      ? CHECK_ENDED.has(view.challenge.stage)
        ? 'done'
        : 'active'
      : decision && !ACTIVE.has(view.status)
        ? 'done'
        : 'waiting';
  return [
    {
      id: 'request',
      state: states.request,
      summary: items === null ? null : t('e1.result.items', { items: count(items, language) }),
    },
    {
      id: 'usual',
      state: states.usual,
      summary:
        decision?.reason?.baselineDeltaCount != null
          ? t('e1.run.differences', { n: decision.reason.baselineDeltaCount })
          : null,
    },
    { id: 'company', state: states.company },
    { id: 'history', state: states.history },
    {
      id: 'prompt',
      state: states.prompt,
      summary: decision ? t('e1.run.tokens', { n: count(decision.promptTokens, language) }) : null,
    },
    {
      id: 'judgement',
      state: states.judgement,
      summary:
        decision?.totalAnalysisMs != null
          ? t('e1.run.judged', { seconds: seconds(decision.totalAnalysisMs) })
          : states.judgement === 'active' && waitedMs !== null
            ? t('e1.run.judging', { seconds: seconds(waitedMs) })
            : null,
    },
    {
      id: 'decision',
      state: states.decision,
      summary: decision ? t(verdictKey(decision.finalAction)) : null,
      detail: decision ? <DecisionDetail {...decisionDetail(t, decision)} /> : undefined,
    },
    {
      id: 'followUp',
      state: followUp,
      summary: checkStage === 'NO_MAILBOX' ? t('e1.run.codeSent') : null,
    },
    { id: 'learning', state: 'waiting' },
  ];
}
