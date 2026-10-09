import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useAnatomy } from '../../../api/anatomy';
import type { LabCase } from '../../../api/lab';
import { useMeasuredCase } from '../../../api/measured';
import { SourceMark } from '../../../components/common/SourceMark';
import { Icon, type IconName } from '../../../components/Icon';
import { JustSaw } from '../../../components/journey/JourneyParts';
import { ActionBar, StepHeader } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { count, seconds } from '../../../journey/format';
import type { Difference } from '../../../journey/journey';
import { stepPath, type Mode, type StepFlow } from '../experience';
import styles from '../Experience.module.css';
import { useTryRun } from './tryRun';

interface CheckStepProps {
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Try 2-7, the identity check (e2-check): what the doubted real employee paid, as the three steps, each with the stored
 * value of that step under it (decided in n s, code accepted, re-sent in n s and n items delivered). It is the visitor's own run when
 * Contexa asked them for a check; otherwise the screen says so plainly and shows the latest measured run that asked for
 * one, naming whether it belongs to the current measurement setting (D-31). Every value is the stored record.
 */
export function CheckStep({ mode, labCase, see, flow }: CheckStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view = run.view;
  const measured = useMeasuredCase(labCase.key).data ?? null;
  const ownAnatomy = useAnatomy(view?.runId ?? null, 1).data ?? null;
  const ownCheck = ownAnatomy?.recovery?.challenge ?? null;
  const ownAnswered = ownCheck?.answered === true && ownCheck.reissue_outcome !== null;
  const example = !ownAnswered ? (measured?.resumed ?? null) : null;
  const exampleAnatomy = useAnatomy(example?.runId ?? null, 1).data ?? null;
  const record = ownAnswered ? ownAnatomy : exampleAnatomy;
  const check = record?.recovery?.challenge ?? null;
  const elapsed = check?.reissue_elapsed_ms ?? null;

  useEffect(() => {
    if (record && check) {
      see(5);
    }
    // Seen once a stored check is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [record !== null && check !== null]);

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!view?.runId) {
    return (
      <>
        <StepHeader title={t('experience.step.check')} purpose={t('e1.run.notSent')} />
        <ActionBar back={{ to: stepPath('owner', 'predict', mode), label: t('e1.run.toPredict') }} />
      </>
    );
  }

  // One figure: each of the three steps with the stored value of that step under it (decided, accepted, re-sent and
  // delivered), so the steps and their timing are read together instead of as two lists.
  const steps: readonly { readonly icon: IconName; readonly text: string; readonly value: string | null }[] =
    [
      {
        icon: 'mail',
        text: t('e2.check.step.code'),
        value: record
          ? t('e2.check.flow.judged', {
              seconds:
                record.interpretation.timings.totalAnalysisMs === null
                  ? '-'
                  : seconds(record.interpretation.timings.totalAnalysisMs),
            })
          : null,
      },
      { icon: 'key', text: t('e2.check.step.enter'), value: record ? t('e2.check.flow.verified') : null },
      {
        icon: 'arrowRight',
        text: t('e2.check.step.resume'),
        value: record
          ? `${t('e2.check.flow.reissued', { seconds: elapsed === null ? '-' : seconds(elapsed) })} · ${t(
              'e2.check.flow.delivered',
              { items: check?.reissue_delivered == null ? '-' : count(check.reissue_delivered, language) },
            )}`
          : null,
      },
    ];
  const exampleDate = example ? new Date(example.startedAt).toISOString().slice(0, 10) : '';

  return (
    <>
      <StepHeader
        title={t(ownAnswered ? 'e2.check.title' : 'e2.check.noneTitle')}
        purpose={t(ownAnswered ? 'e2.check.purpose' : 'e2.check.nonePurpose')}
        source={record ? <SourceMark kind="ENGINE" runId={record.runId} step={1} /> : null}
      />
      {!ownAnswered && example ? (
        <p className={styles.exampleTag}>
          {t(example.current ? 'e2.check.exampleCurrent' : 'e2.check.exampleOld', { date: exampleDate })}
        </p>
      ) : null}
      {record && check ? (
        <>
          <ol className={styles.checkSteps} aria-label={t('e2.check.title')}>
            {steps.map((step, index) => (
              <li key={step.text} className={styles.checkStep}>
                <span className={styles.checkDot}>
                  <Icon name="check" />
                </span>
                <span className={styles.flowNumber}>{index + 1}</span>
                <Icon name={step.icon} className={styles.flowIcon} />
                <span className={styles.flowText}>{step.text}</span>
                {step.value ? <span className={styles.checkValue}>{step.value}</span> : null}
              </li>
            ))}
          </ol>
          <p className={styles.callout}>{t('e2.check.learn')}</p>
          <JustSaw
            difference={5}
            sentence="e2Check"
            values={{ seconds: elapsed === null ? '-' : seconds(elapsed) }}
          />
        </>
      ) : null}
      {!ownAnswered && !example && measured ? <p className={styles.lead}>{t('e2.check.noExample')}</p> : null}
      <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
    </>
  );
}
