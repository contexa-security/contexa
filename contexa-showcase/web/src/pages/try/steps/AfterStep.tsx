import type { TFunction } from 'i18next';
import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useEngineActions, type EngineAction } from '../../../api/engine';
import type { LabCase, LabEmployee } from '../../../api/lab';
import type { LiveDecision } from '../../../api/types';
import { useDetail } from '../../../components/detail/useDetail';
import { Icon, type IconName } from '../../../components/Icon';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { NextLink } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { count } from '../../../journey/format';
import type { Difference } from '../../../journey/journey';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from './AfterStep.module.css';
import { useStoredCheck, useTryAnalysis, useTryRun } from './tryRun';

/** What follows the judgment: held for the security admin, the identity check, the block, or nothing. */
type AfterBranch = 'review' | 'verify' | 'block' | 'none';

/** The guide line of each branch: the copy source's two, and the block's and nothing's own. */
const GUIDES: Readonly<Record<AfterBranch, string>> = {
  review: 'screen.1-6.guide.review',
  verify: 'screen.1-6.guide.verify',
  block: 'p1.after.guide.block',
  none: 'p1.after.guide.none',
};

interface AfterStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly employee: LabEmployee;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

interface FlowItem {
  readonly icon: IconName;
  readonly text: string;
  readonly tone?: 'stop';
}

/**
 * The branch of the visitor's run, from control D's decision of it (F-7); without a decision, an identity check the
 * run recorded still says it asked for one.
 */
function afterBranch(decision: LiveDecision | null, stage: string | null): AfterBranch {
  if (decision && !decision.unresolved) {
    switch (decision.finalAction) {
      case 'ESCALATE':
        return 'review';
      case 'CHALLENGE':
        return 'verify';
      case 'BLOCK':
        return 'block';
      default:
        return 'none';
    }
  }
  return stage ? 'verify' : 'none';
}

/** A hold time as the engine publishes it, in whole minutes where it is whole minutes, else in seconds. */
function holdWords(t: TFunction, seconds: number, language: string): string {
  return seconds % 60 === 0
    ? t('p1.after.minutes', { n: count(seconds / 60, language) })
    : t('p1.after.seconds', { n: count(seconds, language) });
}

/** The figure's steps of a branch; a hold time is the engine's own value for the decision (/api/engine/actions). */
function flowOf(
  t: TFunction,
  branch: AfterBranch,
  hold: EngineAction | undefined,
  nextRequest: boolean,
  employee: LabEmployee,
  language: string,
): readonly FlowItem[] {
  switch (branch) {
    case 'review':
      return [
        { icon: 'lock', text: t(nextRequest ? 'p1.after.review.heldNext' : 'p1.after.review.held') },
        { icon: 'user', text: t('p1.after.review.admin') },
        hold === undefined
          ? { icon: 'clock', text: t('p1.after.review.expireAny'), tone: 'stop' }
          : hold.ttlSeconds === null
            ? { icon: 'clock', text: t('p1.after.review.noExpiry') }
            : {
                icon: 'clock',
                text: t('p1.after.review.expire', { time: holdWords(t, hold.ttlSeconds, language) }),
                tone: 'stop',
              },
      ];
    case 'verify':
      return [
        { icon: 'key', text: t('p1.after.verify.asked') },
        { icon: 'mail', text: t('p1.after.verify.mailbox', { name: employee.displayName }) },
        { icon: 'cross', text: t('p1.after.verify.holder'), tone: 'stop' },
      ];
    case 'block':
      return [
        {
          icon: 'cross',
          text: t(nextRequest ? 'p1.after.block.stoppedNext' : 'p1.after.block.stopped'),
          tone: 'stop',
        },
        {
          icon: 'lock',
          text:
            hold?.ttlSeconds === undefined || hold.ttlSeconds === null
              ? t('p1.after.block.untilLifted')
              : t('p1.after.block.for', { time: holdWords(t, hold.ttlSeconds, language) }),
        },
      ];
    default:
      return [];
  }
}

/**
 * After the stop (화면재편 1-6, T7): what follows the judgment of the visitor's run, as one flow. Held for review:
 * the request waits, a security admin checks it, and past the engine's hold time it is blocked. An identity check: the
 * code goes to the real employee's mailbox, which the person holding the account never receives. A block: it stays
 * until an admin lifts it. One source line says where the judgment and the hold time come from (F-7, V-5).
 */
export function AfterStep({ role, mode, labCase, employee, see, flow }: AfterStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view = run.view;
  const analysis = useTryAnalysis(view, run.stored);
  const actions = useEngineActions();
  const storedStage = useStoredCheck(run.runId, run.stored);
  // How the check went: the live check while the run is current, else the run's stored check.
  const stage = view?.challenge?.stage ?? storedStage;
  const decision = analysis.decision;
  const branch = afterBranch(decision, stage);

  useEffect(() => {
    if (branch !== 'none') {
      see(5);
    }
    // Seen once a follow-up is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [branch !== 'none']);

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!view?.runId) {
    return (
      <ScreenBody
        title={t('screen.1-6.title')}
        purpose={t('p1.unsent.guide')}
        back={null}
        main={<NextLink to={stepPath(role, 'predict', mode)} label={t('p1.unsent.go')} />}
      >
        {null}
      </ScreenBody>
    );
  }
  // The decision is still coming: a stored run's record is being read, or the live run has not ended in a fault.
  const coming =
    !decision && !stage && (run.stored ? !analysis.missing : view.status !== 'FAILED' && view.status !== 'EXPIRED');
  const timed = branch === 'review' || branch === 'block';
  if (coming || (timed && actions.isLoading)) {
    return <StateScreen kind="loading" />;
  }

  const runId = view.runId;
  const hold = branch === 'review' ? actions.data?.ESCALATE : branch === 'block' ? actions.data?.BLOCK : undefined;
  const steps = flowOf(t, branch, hold, decision?.applied === 'NEXT_REQUEST', employee, language);
  const timeShown = hold?.ttlSeconds !== undefined && hold.ttlSeconds !== null;

  return (
    <ScreenBody
      title={t('screen.1-6.title')}
      purpose={t(GUIDES[branch])}
      sourceLine={
        branch === 'none' ? null : (
          <>
            <span>{t(timeShown ? 'p1.after.source.timed' : 'p1.after.source')}</span>
            <button type="button" className={styles.sourceOpen} onClick={() => detail.show(runId, 1)}>
              {t('frame.source.open')}
            </button>
          </>
        )
      }
      back={flow.back}
      main={flow.next}
    >
      {steps.length > 0 ? (
        <ol className={styles.flow} aria-label={t('p1.after.figure')} data-branch={branch}>
          {steps.map((item, index) => (
            <li key={item.icon} className={styles.item}>
              <span className={styles.step} data-tone={item.tone}>
                <Icon name={item.icon} className={styles.icon} />
                <span className={styles.text}>{item.text}</span>
              </span>
              {index < steps.length - 1 ? <Icon name="arrowRight" className={styles.arrow} /> : null}
            </li>
          ))}
        </ol>
      ) : null}
    </ScreenBody>
  );
}
