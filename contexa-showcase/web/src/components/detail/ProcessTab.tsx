import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { DecisionAnatomyView } from '../../api/anatomy';
import { count, seconds } from '../../journey/format';
import { Icon } from '../Icon';
import { VerdictChip } from '../VerdictChip';
import { analysed, STEPS, verdictOf, type Step } from './detailWords';
import { TabFrame, type TabProps } from './TabFrame';
import styles from './DecisionDetail.module.css';

/** The requests the situations send, with words of their own; any other is "a request received". */
const OPERATIONS: ReadonlySet<string> = new Set([
  'CUSTOMER_READ',
  'DOCUMENT_DOWNLOAD',
  'DOCUMENT_READ',
  'EXPORT',
  'EXPORT_ASYNC',
  'EXPORT_STREAM',
  'PROJECT_LIST',
  'ROLE_GRANT',
]);

/**
 * The judgment process (RO-1, RO-11): the nine steps of screen 3-2 by the same names, each with what this request's
 * record says about it: what was asked, how many items differed from the usual, how many company record lines and
 * similar past judgments came in, the text built for the AI, how long the AI took and whether it went on to the deeper
 * analysis, what it proposed against what was applied, what followed and what was learned. A step the record says
 * nothing about says so. The model calls' models, tokens and texts are the original record's.
 */
export function ProcessTab({ view }: TabProps & { readonly view: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  if (!analysed(view)) {
    return (
      <TabFrame>
        <p className={styles.line}>{t('detail.r7.notAnalysedTab')}</p>
      </TabFrame>
    );
  }
  const interpretation = view.interpretation;
  const recorded = interpretation.recorded;
  const timings = interpretation.timings;
  const none = t('detail.r7.noRecord');
  const second = timings.events.some((event) => event.type === 'LAYER2_COMPLETE');
  const documents = view.context.rag?.ragAuthorizedDocumentCount ?? null;
  const check = view.recovery?.challenge ?? null;
  const proposed = verdictOf(recorded.proposedAction);
  const final = verdictOf(recorded.finalAction);

  const values: Readonly<Record<Step, ReactNode>> = {
    request: OPERATIONS.has(view.operation)
      ? t('detail.r7.process.request', { action: t(`detail.r7.operation.${view.operation}`) })
      : t('detail.r7.process.requestOther'),
    usual:
      view.figures.departureCount === null
        ? t('detail.r7.process.usualNone')
        : t('detail.r7.process.usual', { n: count(view.figures.departureCount, language) }),
    company:
      view.juxtaposition.companyFacts.length === 0
        ? t('detail.r7.process.companyNone')
        : t('detail.r7.process.company', { n: count(view.juxtaposition.companyFacts.length, language) }),
    history:
      documents === null
        ? t('detail.r7.process.historyNone')
        : t('detail.r7.process.history', { n: count(documents, language) }),
    prompt:
      timings.promptBuildMs !== null
        ? t('detail.r7.process.promptTime', { s: seconds(timings.promptBuildMs) })
        : view.promptLines
          ? t('detail.r7.process.promptLines', { n: count(view.promptLines.total, language) })
          : none,
    judgement: [
      timings.llmLatencyMs === null
        ? none
        : t('detail.r7.process.answered', { s: seconds(timings.llmLatencyMs) }),
      t(second ? 'detail.r7.process.second' : 'detail.r7.process.firstOnly'),
    ].join(' · '),
    decision: (
      <span className={styles.value}>
        {proposed !== final ? (
          <>
            <span className={styles.label}>{t('detail.r7.process.proposed')}</span>
            <VerdictChip verdict={proposed} />
            <Icon name="arrowRight" />
            <span className={styles.label}>{t('detail.r7.process.applied')}</span>
          </>
        ) : null}
        {/* V-43: the engine records its whole-analysis time as the AI's own time, so step 6 already states it. */}
        <VerdictChip verdict={final} unresolved={recorded.unresolved} />
      </span>
    ),
    followUp: check
      ? t('detail.r7.process.check', {
          result: t(`detail.r7.check.${check.reason ?? (check.answered ? 'DONE' : 'other')}`, {
            defaultValue: t('detail.r7.check.other'),
          }),
        })
      : view.recovery?.release
        ? t('detail.r7.process.release')
        : t('detail.r7.process.followUpNone'),
    learning:
      view.figures.baselineBefore !== null && view.figures.baselineAfter !== null
        ? t('detail.r7.process.learned', {
            before: count(view.figures.baselineBefore, language),
            after: count(view.figures.baselineAfter, language),
          })
        : none,
  };

  return (
    <TabFrame source={t('detail.r7.process.source')}>
      <ol className={styles.steps} aria-label={t('detail.r7.process.figure')}>
        {STEPS.map((id, index) => (
          <li key={id} className={styles.step}>
            {/* The list gives the order to screen readers; the number is drawn for the eye, as on screen 3-2. */}
            <span className={styles.stepNumber} aria-hidden="true">
              {index + 1}
            </span>
            <span className={styles.item}>
              <span className={styles.itemHead}>{t(`p3.how.step.${id}.name`)}</span>
              <span>{values[id]}</span>
            </span>
          </li>
        ))}
      </ol>
    </TabFrame>
  );
}
