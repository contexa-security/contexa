import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { DecisionAnatomyView } from '../../api/anatomy';
import { useStepResult } from '../../api/lab';
import { useRunScore } from '../../api/queries';
import { VERDICTS } from '../../domain/verdict';
import { count, seconds } from '../../journey/format';
import { ActionChip } from '../common/ActionChip';
import { VerdictChip } from '../VerdictChip';
import { analysed, expectedOf, resultKey, verdictOf } from './detailWords';
import { RecordNumber, TabFrame, type TabProps } from './TabFrame';
import { useDetail } from './useDetail';
import styles from './DecisionDetail.module.css';

interface Row {
  readonly key: string;
  readonly value: ReactNode;
  /** Why the value is what it is, when the published rules say so (L-27). */
  readonly note?: string | null;
  /** Where the value comes from, in plain words (the per-number source the screens' chips used to carry). */
  readonly from: string;
}

/**
 * The summary (RO-1): what Contexa judged on this request and where each number comes from, in one table: the
 * judgment, when it applied and how long it took, how much went out, how many requests it had learned before and
 * after, and how the judgment compares with the situation's right handling. Then the reason it gave in plain words
 * (the model's own sentence stays in the original record, V-6, one press away, V-03), what followed, and a failure
 * when there was one. The
 * source line names the record number and when the judgment was recorded. Every value is the server's.
 */
export function SummaryTab({ view, runId, step }: TabProps & { readonly view: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const result = useStepResult(runId, step).data ?? null;
  const score = useRunScore(runId, 'detail', 1).data ?? null;
  const contexa = result?.layers.find((layer) => layer.control === 'D') ?? null;
  const recorded = view.interpretation.recorded;
  const verdict = view.truth.verdict;
  const decidedAt = score?.verdicts.find((entry) => entry.score.stepNo === step)?.decidedAt ?? null;
  const source = <RecordNumber runId={runId} at={decidedAt} />;

  if (!analysed(view)) {
    return (
      <TabFrame source={source}>
        <p className={styles.line}>
          {t(`detail.r7.notAnalysed.${verdict?.source ?? 'NOT_ANALYSED'}`, {
            defaultValue: t('detail.r7.notAnalysed.NOT_ANALYSED'),
          })}
        </p>
        {contexa ? (
          <p className={styles.line}>
            {t('detail.r7.summary.refused')}{' '}
            <code className={styles.original} data-original>
              {contexa.httpStatus ?? '-'} · {contexa.ruleId ?? '-'}
            </code>
          </p>
        ) : null}
      </TabFrame>
    );
  }

  // 판정층 8절 9: a block that cut a streamed response applied while it was sent (the step result's timing); the
  // score's applied names when the later requests are stopped.
  const applied =
    contexa?.evidence.timing === 'MID_RESPONSE'
      ? 'MID_RESPONSE'
      : (verdict?.score.applied ?? recorded.applied);
  const total = view.interpretation.timings.totalAnalysisMs;
  const expected = expectedOf(view.truth.classification);
  const check = view.recovery?.challenge ?? null;
  const finalAction = recorded.finalAction;
  const scored = verdict?.score.result ?? 'NOT_SCORED';
  // L-27: a right handling reached by a judgment other than the plain one (a block to stop, an allow to let through)
  // names that judgment, so "stopped" next to an extra check reads as the check that stopped it.
  const judgedToo =
    scored === 'RIGHT' &&
    expected !== 'none' &&
    finalAction !== null &&
    finalAction !== (expected === 'stop' ? 'BLOCK' : 'ALLOW');
  // L-27: the published learning rule (screen 3-4): a request that did not pass its extra check, or a blocked one, is
  // not added to the usual pattern; the count that stayed the same says so. Any other unchanged count states no reason.
  const notLearned =
    view.figures.baselineBefore !== null &&
    view.figures.baselineBefore === view.figures.baselineAfter &&
    (finalAction === 'BLOCK' || (finalAction === 'CHALLENGE' && check?.answered !== true));
  const learned =
    view.figures.baselineBefore !== null && view.figures.baselineAfter !== null
      ? t('detail.r7.summary.learnedValue', {
          before: count(view.figures.baselineBefore, language),
          after: count(view.figures.baselineAfter, language),
        })
      : t('detail.r7.noRecord');
  const rows: readonly Row[] = [
    {
      key: 'judgment',
      value: <VerdictChip verdict={verdictOf(recorded.finalAction)} unresolved={recorded.unresolved} />,
      from: t('detail.r7.from.decision'),
    },
    {
      key: 'when',
      value: [
        applied && applied !== 'NONE'
          ? t(`detail.r7.applied.${applied}`, { defaultValue: t('detail.r7.applied.other') })
          : t('detail.r7.applied.NONE'),
        ...(total === null ? [] : [t('detail.r7.seconds', { s: seconds(total) })]),
      ].join(' · '),
      from: t('detail.r7.from.decision'),
    },
    {
      key: 'out',
      value: contexa
        ? t('detail.r7.summary.items', { items: count(contexa.evidence.deliveredItems, language) })
        : t('detail.r7.noRecord'),
      from: t('detail.r7.from.response'),
    },
    {
      key: 'learned',
      value: learned,
      note: notLearned ? t('detail.r7.summary.notLearned') : null,
      from: t('detail.r7.from.learning'),
    },
    {
      key: 'right',
      value:
        expected === 'none'
          ? t('detail.r7.expected.none')
          : [
              t(`detail.r7.expected.${expected}`),
              t(resultKey(scored, expected)),
              ...(judgedToo && finalAction !== null
                ? [t('detail.r7.summary.judged', { verdict: t(VERDICTS[verdictOf(finalAction)].labelKey) })]
                : []),
            ].join(' · '),
      from: t(`detail.r7.from.case.${view.truth.truthSource ?? 'NONE'}`, {
        defaultValue: t('detail.r7.from.case.NONE'),
      }),
    },
  ];
  return (
    <TabFrame source={source}>
      <table className={styles.table} aria-label={t('detail.r7.summary.table')}>
        <thead>
          <tr>
            <th scope="col" className={styles.nameCell}>
              {t('detail.r7.summary.col.what')}
            </th>
            <th scope="col">{t('detail.r7.summary.col.value')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <th scope="row" className={styles.nameCell}>
                {t(`detail.r7.summary.row.${row.key}`)}
              </th>
              <td>
                <span className={styles.item}>
                  <span>{row.value}</span>
                  {row.note ? <span>{row.note}</span> : null}
                  <span className={styles.from}>{row.from}</span>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className={styles.group} data-block>
        <p className={styles.title}>{t('detail.r7.summary.reason')}</p>
        {recorded.reasoningCode ? (
          <>
            <p className={styles.line}>
              {t(`reason.canonical.${recorded.reasoningCode}`, { defaultValue: t('detail.r7.summary.free') })}
            </p>
            <p className={styles.aside}>{t('detail.r7.summary.canonical')}</p>
          </>
        ) : recorded.reasoning ? (
          // V-03: the AI's own English sentence stays in the original record (V-6); the line says so and leads there.
          <>
            <p className={styles.line}>{t('detail.r7.summary.free')}</p>
            <div className={styles.actions}>
              <ActionChip icon="arrowRight" size="sm" onClick={() => detail.setTab('original')}>
                {t('detail.r7.summary.toOriginal')}
              </ActionChip>
            </div>
          </>
        ) : (
          <p className={styles.line}>{t('detail.r7.original.noReason')}</p>
        )}
      </div>
      {check ? (
        <p className={styles.line}>
          {t('detail.r7.summary.followUp', {
            result: t(`detail.r7.check.${check.reason ?? (check.answered ? 'DONE' : 'other')}`, {
              defaultValue: t('detail.r7.check.other'),
            }),
          })}
        </p>
      ) : null}
      {recorded.unresolved || recorded.failureType ? (
        <p className={styles.warning} role="note">
          {t('detail.r7.summary.failure')}{' '}
          <code className={styles.original} data-original>
            {recorded.failureType ?? '-'} · {recorded.fallbackCategory ?? '-'}
          </code>
        </p>
      ) : null}
    </TabFrame>
  );
}
