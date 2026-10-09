import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useEngineActions } from '../../../api/engine';
import type { LabCase, LabEmployee } from '../../../api/lab';
import { SourceMark } from '../../../components/common/SourceMark';
import { Icon, type IconName } from '../../../components/Icon';
import { JustSaw } from '../../../components/journey/JourneyParts';
import { ActionBar, StepHeader } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { count } from '../../../journey/format';
import type { Difference } from '../../../journey/journey';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from '../Experience.module.css';
import { useStoredCheck, useTryRun } from './tryRun';

const REASONS = new Set(['NO_MAILBOX', 'EXPIRED', 'ABANDONED', 'DONE', 'FAILED']);

interface AfterStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly employee: LabEmployee;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Try 1-7, the follow-up (e1-after): what happened after the decision, as one flow (the check asked, the code to the
 * real employee's mailbox, the person with the stolen account left without it, the request held) and how long the
 * decision holds the account's next requests (the engine's own value). What the real employee would do is Act 2's
 * subject, and how all checks ended is the follow-up map's (D-41).
 */
export function AfterStep({ role, mode, labCase, employee, see, flow }: AfterStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view = run.view;
  const actions = useEngineActions();
  const storedStage = useStoredCheck(run.runId, run.stored);
  // How the check ended: the live check while the run is current, else the run's stored check.
  const stage = view?.challenge?.stage ?? storedStage;

  useEffect(() => {
    if (stage) {
      see(5);
    }
    // Seen once the follow-up is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stage !== null]);

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!view?.runId) {
    return (
      <>
        <StepHeader title={t('experience.step.after')} purpose={t('e1.run.notSent')} />
        <ActionBar back={{ to: stepPath(role, 'predict', mode), label: t('e1.run.toPredict') }} />
      </>
    );
  }
  if (!stage) {
    return (
      <>
        <StepHeader title={t('experience.step.after')} purpose={t('e1.after.noCheck')} />
        <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
      </>
    );
  }

  const held = view.steps.find((step) => step.stepNo === 1)?.layers.D?.deliveredItems ?? 0;
  const ttl = actions.data?.CHALLENGE?.ttlSeconds ?? null;
  const reason = t(`e1.after.reason.${REASONS.has(stage) ? stage : 'other'}`);
  const steps: readonly { readonly icon: IconName; readonly text: string; readonly tone?: string }[] = [
    { icon: 'key', text: t('e1.after.flow.asked') },
    { icon: 'mail', text: t('e1.after.flow.mailbox', { name: employee.displayName }) },
    { icon: 'cross', text: t('e1.after.flow.attacker'), tone: 'stop' },
    { icon: 'lock', text: t('e1.after.flow.held', { items: count(held, language) }), tone: 'safe' },
  ];

  return (
    <>
      <StepHeader
        title={t('e1.after.title')}
        purpose={t('e1.purpose.after')}
        source={
          <SourceMark kind="ENGINE" runId={view.runId} step={1}>
            {t('e1.after.sourceLine', {
              reason,
              seconds: ttl === null ? '-' : count(ttl, language),
            })}
          </SourceMark>
        }
      />
      <ol className={styles.flowFigure}>
        {steps.map((item, index) => (
          <li key={item.icon} className={styles.flowStep} data-tone={item.tone}>
            <span className={styles.flowNumber}>{index + 1}</span>
            <Icon name={item.icon} className={styles.flowIcon} />
            <span className={styles.flowText}>{item.text}</span>
            {index < steps.length - 1 ? <Icon name="arrowRight" className={styles.flowArrow} /> : null}
          </li>
        ))}
      </ol>
      {ttl !== null ? (
        <p className={styles.callout}>{t('e1.after.holdLine', { minutes: Math.round(ttl / 60) })}</p>
      ) : null}
      <JustSaw difference={5} sentence="e1After" />
      <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
    </>
  );
}
