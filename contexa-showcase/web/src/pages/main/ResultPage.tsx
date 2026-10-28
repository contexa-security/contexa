import { useTranslation } from 'react-i18next';
import { useAnatomy, useReceived } from '../../api/anatomy';
import { useEngineActions } from '../../api/engine';
import { useDetail } from '../../components/detail/useDetail';
import { GhostButton, MainLink, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { useTryRun } from '../try/steps/tryRun';
import { MAIN_CASES, ROLE_PATHS } from './mainCases';
import { ProofPanel } from './ProofPanel';
import styles from './ResultPage.module.css';

/**
 * 2-3, the result (설계서 2-3, IN-6): the headline the visitor's own run makes true, how many comparisons the engine read as
 * outside the usual pattern, what lifts a stopped request, and the five approaches' answers side by side (the proof
 * panel). The reasons, the facts the engine held the request against, are the next screen (2-4, AttackReasonPage).
 * Every value is the run's own record.
 */
export default function ResultPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const key = MAIN_CASES.attacker;
  const run = useTryRun(key, 1);
  const runId = run.view?.status === 'COMPLETED' || run.stored ? run.runId : null;
  const anatomy = useAnatomy(runId, 1);
  const received = useReceived(runId, 1);
  const engineActions = useEngineActions();
  const recorded = anatomy.data?.interpretation.recorded ?? null;
  const contexa = run.view?.steps.find((step) => step.stepNo === 1)?.layers.D ?? null;
  const comparison = received.data ?? null;

  if (run.pending) {
    return (
      <MainScreen title={t('main.2-3.title.pending')} main={null}>
        <StateScreen kind="loading" />
      </MainScreen>
    );
  }
  if (runId === null) {
    return (
      <MainScreen
        title={t('main.2-3.title.none')}
        intro={t('main.2-3.intro.none')}
        main={<MainLink to={ROLE_PATHS.attacker.request}>{t('main.console.toRequest')}</MainLink>}
        nextNote={null}
      >
        {null}
      </MainScreen>
    );
  }
  const action = recorded?.finalAction ?? null;
  const items = contexa?.deliveredItems ?? null;
  const title =
    action === null
      ? t('main.2-3.title.pending')
      : action === 'ALLOW' || (items !== null && items > 0)
        ? t('main.2-3.title.through', { items: count(items ?? 0, language) })
        : t(`main.2-3.title.${action}`);
  return (
    <MainScreen
      title={title}
      intro={
        comparison
          ? t('main.2-3.intro', { n: comparison.departureCount, count: comparison.departureCount }) +
            (action === 'ESCALATE' || action === 'BLOCK' || action === 'CHALLENGE'
              ? ` ${releaseLine(t, action, engineActions.data?.ESCALATE?.ttlSeconds ?? null)}`
              : '')
          : null
      }
    >
      <ProofPanel runId={runId} threat />
      <div className={styles.links}>
        <SourceBadge kind="run" label={t('badge.run')} runId={runId} />
        <GhostButton onClick={() => detail.show(runId, 1, 'summary')}>{t('main.2-3.reasons')}</GhostButton>
      </div>
    </MainScreen>
  );
}

/**
 * What lifts the visitor's stopped request (FU-2): an extra check, a release with the administrator's approval, or for
 * a held request the hold the engine publishes, after which asking again turns it into a block.
 */
function releaseLine(
  t: ReturnType<typeof useTranslation>['t'],
  action: string,
  holdSeconds: number | null,
): string {
  if (action !== 'ESCALATE') {
    return t(`main.2-3.release.${action}`);
  }
  return holdSeconds !== null && holdSeconds % 60 === 0
    ? t('main.2-3.release.ESCALATE', { minutes: holdSeconds / 60 })
    : t('main.2-3.releasePlain.ESCALATE');
}
