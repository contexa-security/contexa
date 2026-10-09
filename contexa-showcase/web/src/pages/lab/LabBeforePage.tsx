import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import type { BeforeSendView } from '../../api/anatomy';
import { useLabBefore, useLabOptions } from '../../api/lab';
import { SourceMark } from '../../components/common/SourceMark';
import { Icon } from '../../components/Icon';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { LabScreen } from './LabScreen';
import { CONDITION_KEYS, conditionText, labQuery, readChanges } from './labPlace';
import styles from './LabPages.module.css';

/** The four conditions of the judgment rules' elevated-risk boundary, in the rule's order. */
const BOUNDARY = ['sensitive', 'established', 'departs', 'approvalMissing'] as const;

function boundaryState(view: BeforeSendView | null): 'applies' | 'clear' | 'unknown' | 'none' {
  if (!view) {
    return 'none';
  }
  return view.boundary.applies === null ? 'unknown' : view.boundary.applies ? 'applies' : 'clear';
}

/**
 * L2-2, the comparison before sending (lab-compare, 7.6): what the engine received in the latest real run of the
 * designed case and of the changed one, side by side: the differences from the usual, the company records flagged and
 * whether the judgment rules' hard line applies (the portal reads its four conditions from the engine's input). A
 * changed case has no right answer set in advance; without a run of the same conditions there is no comparison yet.
 */
export default function LabBeforePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params] = useSearchParams();
  const options = useLabOptions().data ?? null;
  const caseKey = params.get('case');
  const labCase = options?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const changes = readChanges(params);
  const changedKeys = CONDITION_KEYS.filter((key) => changes[key] !== undefined);
  const changed = changedKeys.length > 0;
  const designed = useLabBefore(labCase ? labCase.key : null, null).data?.comparison ?? null;
  const composed = useLabBefore(labCase && changed ? labCase.key : null, changes);
  const now = changed ? (composed.data?.comparison ?? null) : designed;
  const query = labCase ? labQuery(labCase.key, changes) : '';

  if (!options) {
    return <StateScreen kind="loading" />;
  }
  if (!labCase) {
    return (
      <LabScreen
        step="change"
        title={t('labBefore.title')}
        purpose={t('labChange.noCase')}
        back={{ to: '/lab/case', label: t('labChange.back') }}
      >
        {null}
      </LabScreen>
    );
  }
  const text = (key: (typeof CONDITION_KEYS)[number], value: unknown) =>
    conditionText(t, key, value, options, language);
  const purpose = changed
    ? t('labBefore.changed', {
        list: changedKeys
          .map((key) =>
            t('labBefore.change', {
              name: t(`lab.field.${key}`),
              from: text(key, labCase.conditions[key]),
              to: text(key, changes[key]),
            }),
          )
          .join(' · '),
      })
    : t('labBefore.asDesigned');
  const cells = [
    { key: 'usual', before: designed?.departureCount ?? null, now: now?.departureCount ?? null },
    { key: 'company', before: designed?.companyAdverseCount ?? null, now: now?.companyAdverseCount ?? null },
  ] as const;
  const answer =
    labCase.classification === 'THREAT' ? 'stop' : labCase.classification === 'NORMAL' ? 'pass' : 'none';
  return (
    <LabScreen
      step="change"
      title={t('labBefore.title')}
      purpose={purpose}
      source={
        now ? (
          <SourceMark kind="ENGINE" runId={now.runId} step={1}>
            {t('labBefore.source')}
          </SourceMark>
        ) : null
      }
      back={{ to: `/lab/change?${query}`, label: t('labBefore.back') }}
      main={<NextLink to={`/lab/send?${query}`} label={t('labBefore.next')} />}
    >
      <div className={styles.compareCells}>
        {cells.map((cell) => (
          <section key={cell.key} className={styles.compareCell} aria-labelledby={`before-${cell.key}`}>
            <h2 id={`before-${cell.key}`} className={styles.panelTitle}>
              {t(`labBefore.cell.${cell.key}`)}
            </h2>
            <p className={styles.compareValue}>
              {changed ? (
                <>
                  <span>{cell.before ?? '-'}</span>
                  <Icon name="arrowRight" className={styles.compareArrow} />
                </>
              ) : null}
              <span className={styles.compareNow}>{cell.now ?? '-'}</span>
            </p>
          </section>
        ))}
        <section className={styles.compareCell} aria-labelledby="before-line">
          <h2 id="before-line" className={styles.panelTitle}>
            {t('labBefore.cell.line')}
          </h2>
          <p className={styles.compareValue}>
            {changed ? (
              <>
                <span>{t(`labBefore.line.${boundaryState(designed)}`)}</span>
                <Icon name="arrowRight" className={styles.compareArrow} />
              </>
            ) : null}
            <span className={styles.compareNow}>{t(`labBefore.line.${boundaryState(now)}`)}</span>
          </p>
          {now ? (
            <ul className={styles.lineConditions}>
              {BOUNDARY.map((condition) => {
                const value = now.boundary[condition];
                return (
                  <li key={condition} data-met={value === true || undefined}>
                    <Icon name={value === true ? 'check' : value === false ? 'cross' : 'dash'} />
                    {t(`labBefore.condition.${condition}`)}
                  </li>
                );
              })}
            </ul>
          ) : null}
        </section>
      </div>
      {changed && !composed.isPending && now === null ? (
        <p className={styles.note}>{t('labBefore.noRecord')}</p>
      ) : null}
      <p className={styles.truth}>{changed ? t('labBefore.noAnswer') : t(`labBefore.answer.${answer}`)}</p>
    </LabScreen>
  );
}
