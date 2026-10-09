import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useParams, useSearchParams } from 'react-router-dom';
import { useStepResult } from '../api/lab';
import { useMeasuredCase, type MeasuredCase } from '../api/measured';
import { useReplay, useStoredRunScores } from '../api/queries';
import type { Layer, RunScore } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { ActionChip } from '../components/common/ActionChip';
import { SourceMark } from '../components/common/SourceMark';
import { useDetail } from '../components/detail/useDetail';
import { ActionBar, MoreRow, NextLink } from '../components/journey/StepParts';
import { measuredLine } from '../components/replay/replayLine';
import { ReplayStage, type ReplayColumnData } from '../components/replay/ReplayStage';
import { StateScreen } from '../components/StateScreen';
import styles from './ReplayPage.module.css';

/** Only an address inside the demo is a way back. */
function wayBack(from: string | null): string | null {
  return from && /^\/(?!\/)/.test(from) ? from : null;
}

/**
 * The stored real record of a case (D-35, T-111): where a visitor goes when today's live runs are spent. A pair the
 * operator recorded from a measurement (work 6) replays its recorded runs, the first screen's two columns; any other
 * case replays the middle run of its current measurement. Every answer is the run's record; the way back returns to
 * the screen the visitor came from.
 */
export default function ReplayPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { pairKey = '' } = useParams();
  const [params] = useSearchParams();
  const back = wayBack(params.get('from'));
  const detail = useDetail();
  const recording = useReplay(pairKey);
  const measured = useMeasuredCase(recording.isError ? pairKey : null);
  const middle = measured.data?.middleRun ?? null;
  const middleResult = useStepResult(middle, 1).data ?? null;
  const scenes = recording.data?.scenes ?? [];
  const runIds = recording.data ? scenes.map((scene) => scene.runId) : middle ? [middle] : [];
  const scores = useStoredRunScores(runIds).map((query) => query.data ?? null);

  const columns: ReplayColumnData[] = recording.data
    ? scenes.map((scene, index) =>
        column(t, language, scene.runId, scores[index] ?? null, scene.layers, {
          runs: scene.repetitions,
          same: scene.agreeing,
          passedAfterCheck: 0,
        }),
      )
    : measured.data && middle && middleResult
      ? [
          column(
            t,
            language,
            middle,
            scores[0] ?? null,
            middleResult.layers,
            measuredCounts(measured.data, scores[0]),
          ),
        ]
      : [];
  const ready = columns.length > 0 && scores.every((score) => score !== null);
  const missing = recording.isError && (measured.isError || (measured.isSuccess && !middle));
  const steps = Math.max(...scores.map((score) => score?.executedSteps ?? 1), 1);

  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <header className={styles.head}>
          <h1 className={styles.title}>{t('replay2.title')}</h1>
          <p className={styles.sub}>{t('replay2.sub')}</p>
        </header>
        <div className={styles.stage}>
          {missing ? <StateScreen kind="notReady" /> : null}
          {!missing && !ready ? <StateScreen kind="loading" /> : null}
          {ready ? (
            <>
              <ReplayStage
                source={
                  <SourceMark kind="MEASUREMENT" runId={runIds[0] ?? null} measured>
                    {recording.data
                      ? t('replay2.sourceRecorded', {
                          runs: runIds.join(', '),
                          at: scenes[0]?.recordedAt.slice(0, 10) ?? '-',
                        })
                      : t('replay2.sourceMeasured', {
                          run: middle ?? '-',
                          protocol: measured.data?.protocolId ?? '-',
                          runs: measured.data?.runs ?? 0,
                        })}
                  </SourceMark>
                }
                columns={columns}
              />
              {steps > 1 ? <p className={styles.note}>{t('replay2.firstRequest', { n: steps })}</p> : null}
            </>
          ) : null}
        </div>
        {ready ? (
          <MoreRow>
            {columns.map((entry, index) => (
              <ActionChip
                key={entry.key}
                onClick={() => detail.show(runIds[index] ?? entry.key)}
                icon="search"
                variant="open"
              >
                {columns.length > 1 ? t('replay2.detailOf', { name: entry.title }) : t('e1.result.detail')}
              </ActionChip>
            ))}
          </MoreRow>
        ) : null}
        <ActionBar
          main={
            back ? (
              <NextLink to={back} label={t('replay2.back')} />
            ) : (
              <NextLink to="/" label={t('replay2.home')} />
            )
          }
          skip={false}
        />
      </main>
    </>
  );
}

interface Counts {
  readonly runs: number;
  readonly same: number;
  readonly passedAfterCheck: number;
}

/** A case's current measurement as the column's line: its runs, how many had the middle run's result, and so on. */
function measuredCounts(measured: MeasuredCase, score: RunScore | null | undefined): Counts {
  const result = score?.business['D']?.result ?? null;
  return {
    runs: measured.runs,
    same: result === null ? 0 : (measured.results[result] ?? 0),
    passedAfterCheck: measured.results['PASSED_AFTER_CHECK'] ?? 0,
  };
}

/** One recorded run as a replayed column: the case's name and right answer from the run's own score. */
function column(
  t: TFunction,
  language: string,
  runId: string,
  score: RunScore | null,
  layers: readonly Layer[],
  counts: Counts,
): ReplayColumnData {
  const classification = score?.truth.classification ?? null;
  const normal = classification === 'NORMAL';
  return {
    key: runId,
    title: score?.title?.[language] ?? t('detail.unnamed'),
    answer: t(
      classification === 'THREAT'
        ? 'hook.answer.stop'
        : classification === 'NORMAL'
          ? 'hook.answer.pass'
          : 'labCase.answer.none',
    ),
    normal,
    layers,
    correct: score?.correct,
    measured: measuredLine(t, counts.runs, counts.same, counts.passedAfterCheck, normal),
  };
}
