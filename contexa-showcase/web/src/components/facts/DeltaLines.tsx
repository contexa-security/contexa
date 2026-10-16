import { useTranslation } from 'react-i18next';
import type { DeltaStep, LabDelta } from '../../api/promptQuality';
import type { Verdict } from '../../domain/verdict';
import { Icon } from '../Icon';
import { VerdictChip } from '../VerdictChip';
import { factKey } from './factWords';
import styles from './Facts.module.css';

interface DeltaLinesProps {
  readonly delta: LabDelta;
  /** Contexa's first decision in the run, shown at the end of the first request's flow. */
  readonly verdict: Verdict;
}

/** The server's delivery check of a step: not compared, the value in its line only, or lines changed unexpectedly. */
function StepCheck({ step }: { readonly step: DeltaStep }) {
  const { t } = useTranslation();
  if (step.notCompared !== null) {
    return (
      <p className={styles.check} data-ok="pending">
        <Icon name="dash" />
        {t(`labDelta.notCompared.${step.notCompared}`)}
      </p>
    );
  }
  return (
    <>
      <p className={styles.check} data-ok={step.passed}>
        <Icon name={step.passed ? 'check' : 'cross'} />
        {step.passed
          ? typeof step.unchangedLines === 'number'
            ? t('labDelta.passedCount', { n: step.unchangedLines })
            : t('labDelta.passed')
          : t('labDelta.failed')}
      </p>
      {!step.passed && step.unexpected.length > 0 ? (
        <ul className={`${styles.deltaLines} ${styles.wide}`} aria-label={t('labDelta.unexpected')}>
          {step.unexpected.map((label) => (
            <li key={label} data-unexpected>
              <span>{t(`fact.label.${factKey(label)}`)}</span>{' '}
              <code className={styles.deltaValue} data-original>
                {label}
              </code>
            </li>
          ))}
        </ul>
      ) : null}
      {step.valueMatches === false ? <p className={styles.check}>{t('labDelta.valueMissed')}</p> : null}
    </>
  );
}

/**
 * The lab result's changed lines (U-5, lab-3): the condition changed, the lines of the AI input it changed (before and
 * after, as sent) and the decision, joined by arrows, then the server's delivery check: the changed value went into
 * that line only, or a cross with the lines that changed though they were not expected to (C-22). A step the server
 * did not compare says so and is never shown as passed; a run without a delta says why.
 */
export function DeltaLines({ delta, verdict }: DeltaLinesProps) {
  const { t } = useTranslation();
  const condition = delta.condition
    ? t(`lab.fieldInline.${delta.condition}`, { defaultValue: t('fact.label.other') })
    : '-';
  return (
    <section className={styles.delta} aria-labelledby="lab-delta">
      <h2 id="lab-delta" className={styles.deltaTitle}>
        {t('labDelta.title')}
      </h2>
      {!delta.available ? (
        <p className={styles.empty} data-state="not-available">
          {t(`labDelta.reason.${delta.reason ?? 'other'}`, { defaultValue: t('labDelta.reason.other') })}
        </p>
      ) : null}
      {delta.available
        ? delta.steps.map((step, index) => (
            <div key={step.stepNo} className={styles.deltaFlow} data-step={step.stepNo}>
              {delta.steps.length > 1 ? (
                <p className={styles.deltaStep}>{t('labDelta.step', { n: step.stepNo })}</p>
              ) : null}
              <div className={styles.deltaCell}>
                <span className={styles.chainLabel}>{t('labDelta.condition')}</span>
                <span className={styles.factName}>{condition}</span>
                {delta.value !== null ? (
                  <code className={styles.deltaValue} data-original>
                    {delta.value}
                  </code>
                ) : null}
              </div>
              <Icon name="arrowRight" className={styles.arrow} />
              <div className={styles.deltaCell}>
                <span className={styles.chainLabel}>{t('labDelta.lines')}</span>
                {step.changed.length > 0 ? (
                  <ul className={styles.deltaLines} aria-label={t('labDelta.lines')}>
                    {step.changed.map((line) => (
                      <li key={line.label} data-unexpected={step.unexpected.includes(line.label) || undefined}>
                        <span>{t(`fact.label.${factKey(line.label)}`)}</span>{' '}
                        <code className={styles.deltaValue} data-original>
                          {`${line.label}: ${line.before.join(' | ') || '-'} → ${line.after.join(' | ') || '-'}`}
                        </code>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className={styles.empty}>{t('labDelta.none')}</span>
                )}
              </div>
              {index === 0 ? (
                <>
                  <Icon name="arrowRight" className={styles.arrow} />
                  <div className={styles.deltaCell}>
                    <span className={styles.chainLabel}>{t('labDelta.decision')}</span>
                    <VerdictChip verdict={verdict} />
                  </div>
                </>
              ) : null}
              <StepCheck step={step} />
            </div>
          ))
        : null}
    </section>
  );
}
