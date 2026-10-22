import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useAnatomy } from '../../../api/anatomy';
import type { LabCase } from '../../../api/lab';
import { useMeasuredCase } from '../../../api/measured';
import { Icon, type IconName } from '../../../components/Icon';
import { SourceLine } from '../../../components/journey/FrameParts';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { NextLink } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { count, seconds } from '../../../journey/format';
import type { Difference } from '../../../journey/journey';
import { stepPath, type Mode, type StepFlow } from '../experience';
import styles from './AfterStep.module.css';
import { useTryRun } from './tryRun';

interface CheckStepProps {
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

interface CheckItem {
  readonly icon: IconName;
  readonly text: string;
  readonly value: string;
}

/**
 * Screen 2-5, the identity check (화면재편 T7): how a doubted real employee gets through, as the three steps of one
 * finished check, each with its stored value under it (judged in n s, code accepted, the original request out again
 * in n s with n records). The check is the visitor's own when Contexa asked them and they entered the code on 2-2;
 * otherwise the guide says so and the screen shows another real request that finished a check, its source line naming
 * whether it was sent under the current setting (D-31, V-20). Every value is the stored record.
 */
export function CheckStep({ mode, labCase, see, flow }: CheckStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const run = useTryRun(labCase.key, labCase.requests.length);
  const runId = run.view?.runId ?? null;
  const own = useAnatomy(runId, 1);
  const ownCheck = own.data?.recovery?.challenge ?? null;
  const ownAnswered = ownCheck?.answered === true && ownCheck.reissue_outcome !== null;
  const measured = useMeasuredCase(labCase.key);
  const example = ownAnswered ? null : (measured.data?.resumed ?? null);
  const other = useAnatomy(example?.runId ?? null, 1);
  const record = ownAnswered ? (own.data ?? null) : (other.data ?? null);
  const check = record?.recovery?.challenge ?? null;

  useEffect(() => {
    if (record && check) {
      see(5);
    }
    // Seen once a finished check is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [record !== null && check !== null]);

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!runId) {
    return (
      <ScreenBody
        title={t('screen.2-5.title')}
        purpose={t('p1.unsent.guide')}
        back={null}
        main={<NextLink to={stepPath('owner', 'predict', mode)} label={t('p1.unsent.go')} />}
      >
        {null}
      </ScreenBody>
    );
  }
  if (own.isPending || (!ownAnswered && (measured.isPending || (example !== null && other.isPending)))) {
    return <StateScreen kind="loading" />;
  }

  const shown = record !== null && check !== null;
  const guide = ownAnswered
    ? 'screen.2-5.guide'
    : !shown
      ? 'p2.check.guide.noExample'
      : ownCheck
        ? 'p2.check.guide.unfinished'
        : 'p2.check.guide.notAsked';
  const analysisMs = record?.interpretation.timings.totalAnalysisMs ?? null;
  const elapsed = check?.reissue_elapsed_ms ?? null;
  const delivered = check?.reissue_delivered ?? null;
  const items: readonly CheckItem[] = shown
    ? [
        {
          icon: 'mail',
          text: t('p2.check.step.code'),
          value: t('p2.check.value.judged', { seconds: analysisMs === null ? '-' : seconds(analysisMs) }),
        },
        { icon: 'key', text: t('p2.check.step.enter'), value: t('p2.check.value.verified') },
        {
          icon: 'arrowRight',
          text: t('p2.check.step.resume'),
          value: t('p2.check.value.resent', {
            seconds: elapsed === null ? '-' : seconds(elapsed),
            items: delivered === null ? '-' : count(delivered, language),
          }),
        },
      ]
    : [];

  return (
    <ScreenBody
      title={t('screen.2-5.title')}
      purpose={t(guide)}
      sourceLine={
        shown && record ? (
          <SourceLine
            kind={ownAnswered ? 'run' : example?.current ? 'earlier' : 'older'}
            runId={record.runId}
          />
        ) : null
      }
      back={flow.back}
      main={flow.next}
    >
      {items.length > 0 ? (
        <ol className={styles.flow} aria-label={t('p2.check.figure')} data-branch="verify">
          {items.map((item, index) => (
            <li key={item.icon} className={styles.item}>
              <span className={styles.step}>
                <Icon name={item.icon} className={styles.icon} />
                <span className={styles.text}>{item.text}</span>
                <span className={styles.value}>{item.value}</span>
              </span>
              {index < items.length - 1 ? <Icon name="arrowRight" className={styles.arrow} /> : null}
            </li>
          ))}
        </ol>
      ) : null}
    </ScreenBody>
  );
}
