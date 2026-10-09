import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useHook, type HookColumn } from '../../api/hook';
import { useLabOptions } from '../../api/lab';
import { useVisitor } from '../../api/queries';
import { useTeasers } from '../../api/teasers';
import { AppHeader } from '../../components/AppHeader';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { TeaserBand } from '../../components/journey/Cards';
import { JourneyBar } from '../../components/journey/JourneyParts';
import { ActionBar, NextLink } from '../../components/journey/StepParts';
import { measuredLine } from '../../components/replay/replayLine';
import { ReplayStage, type ReplayColumnData } from '../../components/replay/ReplayStage';
import { StateScreen } from '../../components/StateScreen';
import { teaserCopy } from '../../journey/copy';
import { count } from '../../journey/format';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import styles from './HookPage.module.css';

/**
 * The first screen (hook, 0-3): one message, that the same account, permission and request were told apart only by
 * Contexa. The stored measured runs of the export by someone with a stolen account and by the real employee replay side
 * by side, every approach's answer from the record with right or wrong by the one scoring rule, Contexa's last after
 * its real deciding time. The question that leads on is the teaser band's (D-41); the runs and the measurement behind
 * the replay are in its one source tag.
 */
export default function HookPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  useVisitor();
  const position = useJourneyPosition();
  const hook = useHook();
  const teasers = useTeasers();
  const options = useLabOptions();
  const attackerCase = options.data?.cases.find((candidate) => candidate.key === hook.data?.attacker.caseKey);
  const slot = options.data?.timeSlots.find(
    (candidate) => candidate.slot === attackerCase?.conditions.timeSlot,
  );
  const items = attackerCase?.requests[0]?.items ?? null;
  const copy = teaserCopy(t, language, 'HOOK_TRY', teasers.data, position.differences.length);
  // The question keeps its line before the record arrives; only the record decides which question is true.
  const question = hook.data ? t(hook.data.distinguished ? 'hook.question' : 'hook.questionFallback') : ' ';

  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <JourneyBar />
        <header className={styles.head}>
          <h1 className={styles.title}>{t('hook.title')}</h1>
          <p className={styles.sub}>
            {slot && items !== null
              ? t('hook.sub', {
                  when: t(`lab.slot.${slot.slot}`, { time: slot.representativeTime }),
                  items: count(items, language),
                })
              : ' '}
          </p>
        </header>
        {/* The replay keeps its place while the record loads, so nothing below it moves when it arrives. */}
        <div className={styles.stage}>
          {hook.isPending ? <StateScreen kind="loading" /> : null}
          {hook.isError ? <StateScreen kind="notReady" /> : null}
          {hook.data ? (
            <>
              <ReplayStage
                source={
                  <SourceMark kind="MEASUREMENT" runId={hook.data.attacker.runId} measured>
                    {t('hook.source', {
                      attacker: hook.data.attacker.runId,
                      owner: hook.data.owner.runId,
                      protocol: hook.data.attacker.measurement.protocolId,
                    })}
                  </SourceMark>
                }
                columns={[
                  hookColumn(t, 'attacker', hook.data.attacker),
                  hookColumn(t, 'owner', hook.data.owner),
                ]}
              />
              <p className={styles.note}>{t('hook.note')}</p>
            </>
          ) : null}
        </div>
        {/* The three ways in (0-3): the one main button under the question, the other two on the left. */}
        <ActionBar
          teaser={<TeaserBand copy={{ ...copy, question }} />}
          main={<NextLink to="/try/attacker/scene" label={t('hook.try')} />}
          start={
            <>
              <ActionChip to="/intro?route=intro" icon="book">
                {t('hook.concept')}
              </ActionChip>
              <ActionChip to="/benchmark" icon="chart">
                {t('hook.benchmark')}
              </ActionChip>
            </>
          }
          skip={false}
        />
      </main>
    </>
  );
}

/** A case of the hook as a replayed column: the stolen account's export, or the real employee's approved one. */
function hookColumn(t: TFunction, side: 'attacker' | 'owner', column: HookColumn): ReplayColumnData {
  const measurement = column.measurement;
  return {
    key: side,
    title: t(side === 'attacker' ? 'hook.attacker' : 'hook.owner'),
    answer: t(side === 'attacker' ? 'hook.answer.stop' : 'hook.answer.pass'),
    normal: side === 'owner',
    layers: column.result.layers,
    correct: column.correct,
    measured: measuredLine(
      t,
      measurement.runs,
      measurement.sameResult,
      measurement.passedAfterCheck,
      side === 'owner',
    ),
  };
}
