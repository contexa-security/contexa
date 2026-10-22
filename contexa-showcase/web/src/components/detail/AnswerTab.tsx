import { useTranslation } from 'react-i18next';
import type { DecisionAnatomyView } from '../../api/anatomy';
import { count } from '../../journey/format';
import { VerdictChip } from '../VerdictChip';
import { expectedOf, verdictOf } from './detailWords';
import { TabFrame, type TabProps } from './TabFrame';
import styles from './DecisionDetail.module.css';
import { inCurrentWords } from '../../domain/caseWords';
import { keepWhole } from './keepWhole';

/** A project or ticket code in a quoted text (HX-310, GB-500), kept whole on a line (L-27). */
const CODE = /\b[A-Z]{2,}-\d+\b/g;

/**
 * The right handling (RO-1, 기획안 11.2 '정답'): whether the situation is a request to stop or one to let through, as
 * its definition set it in advance from the company records, the judgments that count as handling it right, why, the
 * objection one could raise, and what happened to the whole situation's work. The reason and the objection are the
 * situation definition's own words, quoted as stored with the request (frozen with its hash, which the source line
 * names); the tab never rewrites them.
 */
export function AnswerTab({ view }: TabProps & { readonly view: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const truth = view.truth;
  const expected = expectedOf(truth.classification);
  return (
    <TabFrame
      source={
        <>
          <span>
            {t(`detail.r7.from.case.${truth.truthSource ?? 'NONE'}`, {
              defaultValue: t('detail.r7.from.case.NONE'),
            })}
          </span>
          {truth.scenarioSha256 ? (
            // L-27: the separator is a piece of its own, so the line's gaps space it like the rest.
            <>
              <span aria-hidden="true">·</span>
              <span>{t('detail.r7.answer.hash')}</span>
              <code className={styles.original} data-original>
                {truth.scenarioSha256.slice(0, 12)}
              </code>
            </>
          ) : null}
        </>
      }
    >
      <div className={styles.group} data-block>
        <p className={styles.title}>{t(`detail.r7.expected.${expected}`)}</p>
        {truth.allowedEngineActions.length > 0 ? (
          <p className={styles.value}>
            <span className={styles.label}>{t('detail.r7.answer.allowed')}</span>
            {truth.allowedEngineActions.map((action) => (
              <VerdictChip key={action} verdict={verdictOf(action)} />
            ))}
          </p>
        ) : null}
      </div>
      <section className={styles.group} aria-labelledby="detail-answer-why" data-block>
        <h3 id="detail-answer-why" className={styles.title}>
          {t('detail.r7.answer.why')}
        </h3>
        {truth.rationale?.[language] ? (
          // The situation definition's own words, quoted as stored with the request (its hash is on the source line).
          // P-29: they keep the definition's plain style; the line under them says why they are not reworded.
          <>
            <blockquote className={styles.quote} data-original>
              {keepWhole(inCurrentWords(truth.rationale[language], language), CODE, styles.whole)}
            </blockquote>
            <p className={styles.aside}>{t('detail.r7.answer.asStored')}</p>
          </>
        ) : (
          <p className={styles.line}>{t('detail.r7.answer.noWhy')}</p>
        )}
      </section>
      {truth.counterpoint?.[language] ? (
        <section className={styles.group} aria-labelledby="detail-answer-counterpoint" data-block>
          <h3 id="detail-answer-counterpoint" className={styles.title}>
            {t('detail.r7.answer.counterpoint')}
          </h3>
          <blockquote className={styles.quote} data-original>
            {keepWhole(inCurrentWords(truth.counterpoint[language], language), CODE, styles.whole)}
          </blockquote>
        </section>
      ) : null}
      {truth.business ? (
        <p className={styles.line}>
          {t('detail.r7.answer.business', {
            result: t(`detail.r7.business.${truth.business.result}`, {
              defaultValue: t('detail.r7.business.other'),
            }),
            items: count(truth.business.exposedItems, language),
          })}
        </p>
      ) : null}
    </TabFrame>
  );
}
