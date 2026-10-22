import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useParams, useSearchParams } from 'react-router-dom';
import { useMeasuredCase, type MeasuredCase } from '../api/measured';
import { useReplay, useStoredRunScores } from '../api/queries';
import type { CaseResult, RunScore, Scene } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { useDetail } from '../components/detail/useDetail';
import { DetailChip } from '../components/journey/FrameParts';
import chip from '../components/journey/FrameParts.module.css';
import { ScreenBody } from '../components/journey/ScreenBody';
import { NextLink } from '../components/journey/StepParts';
import { Icon } from '../components/Icon';
import { StateScreen } from '../components/StateScreen';
import { VerdictChip } from '../components/VerdictChip';
import { CONTROL_ORDER, VERDICTS, type ControlId, type Verdict } from '../domain/verdict';
import { count } from '../journey/format';
import results from './try/steps/ResultStep.module.css';
import frame from './try/Experience.module.css';
import styles from './ReplayPage.module.css';

/** Only an address inside the demo is a way back. */
function wayBack(from: string | null): string | null {
  return from && /^\/(?!\/)/.test(from) ? from : null;
}

/** The plain word of each scored result, the same words as the result screens (화면재편-기획안 11.2). */
const RESULT_WORDS: Readonly<Partial<Record<CaseResult, string>>> = {
  STOPPED: 'p1.result.word.STOPPED',
  PARTLY_STOPPED: 'p1.result.word.PARTLY_STOPPED',
  MISSED: 'p1.result.word.MISSED',
  PASSED: 'p1.result.word.PASSED',
  PASSED_AFTER_CHECK: 'p1.result.word.PASSED_AFTER_CHECK',
  HALTED: 'p1.result.word.HALTED',
  UNRESOLVED: 'p1.result.word.UNRESOLVED',
};

/** One stored run shown as one column of the table. */
interface Column {
  readonly runId: string;
  /** Who sent it (a recorded pair) or what it should get (a measured run). */
  readonly name: string;
  readonly score: RunScore;
  /** How the same situation came out when it was sent several times. */
  readonly repeat: string;
}

/**
 * The stored real record of a situation (D-35, 화면재편-구현계획 5절 RO-5): where a visitor goes when today's live sends
 * are spent or paused. A pair recorded from repeated sends shows its two runs side by side (the person with a stolen
 * account and the real employee), any other situation the middle run of its current repeated sends. Every cell is the
 * server's score of that stored run; the way back returns to the screen the visitor came from.
 */
export default function ReplayPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { pairKey = '' } = useParams();
  const [params] = useSearchParams();
  const back = wayBack(params.get('from'));
  const recording = useReplay(pairKey);
  const measured = useMeasuredCase(recording.isError ? pairKey : null);
  const middle = measured.data?.middleRun ?? null;
  const scenes = recording.data?.scenes ?? [];
  const runIds = recording.data ? scenes.map((scene) => scene.runId) : middle ? [middle] : [];
  const scoreQueries = useStoredRunScores(runIds);
  const scores = scoreQueries.map((query) => query.data ?? null);
  // Each recorded scene's situation in the current measurement: whether the recorded run is one of its runs (V-18).
  const firstCase = useMeasuredCase(recording.data ? (scores[0]?.scenarioKey ?? null) : null);
  const secondCase = useMeasuredCase(recording.data ? (scores[1]?.scenarioKey ?? null) : null);
  const sceneCases = [firstCase, secondCase];
  // No recording and no repeated sends, or a stored run whose score the server does not give: the record is not there.
  const missing =
    (recording.isError && (measured.isError || (measured.isSuccess && !middle))) ||
    scoreQueries.some((query) => query.isError);
  const ready = runIds.length > 0 && scores.every((score) => score !== null);
  const columns: readonly Column[] = ready
    ? recording.data
      ? scenes.map((scene, index) => pairColumn(t, scene, scores[index] as RunScore))
      : measured.data && middle
        ? [measuredColumn(t, middle, scores[0] as RunScore, measured.data)]
        : []
    : [];
  const steps = Math.max(1, ...columns.map((column) => column.score.executedSteps));

  return (
    <>
      <AppHeader space={{ name: t('frame.space.replay') }} />
      <main id="main" className={frame.page} data-type="T5">
        <ScreenBody
          title={t('space.r7.replay.title')}
          purpose={t('space.r7.replay.guide')}
          back={null}
          main={<NextLink to={back ?? '/'} label={t(back ? 'replay2.back' : 'replay2.home')} />}
          more={columns.length > 0 ? <DetailButtons columns={columns} /> : null}
          sourceLine={
            columns.length === 0
              ? null
              : withDay(
                  sourceLine(t, scenes, columns),
                  recording.data
                    ? recordingDay(t, scenes, sceneCases)
                    : measuredDay(t, middle, measured.data),
                )
          }
        >
          {missing ? <StateScreen kind="notReady" /> : null}
          {!missing && columns.length === 0 ? <StateScreen kind="loading" /> : null}
          {columns.length > 0 ? (
            <>
              {recording.data ? (
                // One line per situation, named as its column is (V-18): the attack and the normal work differ.
                <ul className={styles.situations} aria-label={t('space.r7.replay.situations')}>
                  {scenes.map((scene) => (
                    <li key={scene.recordId} className={styles.situation}>
                      <b className={styles.situationName}>{t(`space.r7.replay.col.${scene.kind}`)}</b>{' '}
                      {scene.sentence[language]}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className={styles.situation}>{t(expectedKey(columns[0]?.score.truth.classification ?? null))}</p>
              )}
              {recording.data ? <PairTable columns={columns} /> : <RunTable column={columns[0] as Column} />}
              {steps > 1 ? (
                <p className={styles.note}>{t('space.r7.replay.steps', { n: count(steps, language) })}</p>
              ) : null}
            </>
          ) : null}
        </ScreenBody>
      </main>
    </>
  );
}

/** A recorded scene's column: named by its situation (V-18), its repeated sends from the recording. */
function pairColumn(t: TFunction, scene: Scene, score: RunScore): Column {
  return {
    runId: scene.runId,
    name: t(`space.r7.replay.col.${scene.kind}`),
    score,
    repeat: repeatLine(t, scene.repetitions, scene.agreeing, 0, false),
  };
}

/** The middle run of a situation's current repeated sends: how many of them had its result, or passed after a check. */
function measuredColumn(t: TFunction, runId: string, score: RunScore, measured: MeasuredCase): Column {
  const result = score.business.D?.result ?? null;
  const normal = score.truth.classification === 'NORMAL';
  return {
    runId,
    name: t('e1.result.table.result'),
    score,
    repeat: repeatLine(
      t,
      measured.runs,
      result === null ? 0 : (measured.results[result] ?? 0),
      measured.results.PASSED_AFTER_CHECK ?? 0,
      normal,
    ),
  };
}

/**
 * The screen's one source line (R-10): the stored run is one of the same situation's repeated real sends, with how
 * often they agreed; a pair whose runs all agreed the same number of times says so in one sentence.
 */
function sourceLine(t: TFunction, scenes: readonly Scene[], columns: readonly Column[]): string {
  const [first] = scenes;
  if (
    first &&
    scenes.length === columns.length &&
    scenes.every((scene) => scene.agreeing === scene.repetitions && scene.repetitions === first.repetitions)
  ) {
    return t('space.r7.replay.sourceSame', { runs: first.repetitions });
  }
  return `${t('space.r7.replay.source')} · ${columns
    .map((column) => (columns.length > 1 ? `${column.name}: ${column.repeat}` : column.repeat))
    .join(', ')}`;
}

/** The source line with the day of its measurement, when that is known. */
function withDay(line: string, day: string | null): string {
  return day ? `${line} · ${day}` : line;
}

/** The day a run of the current measurement started, as its list records it; null when it is not in the list. */
function startedDay(runId: string | null, measured: MeasuredCase | undefined): string | null {
  return measured?.list.find((run) => run.runId === runId)?.startedAt?.slice(0, 10) ?? null;
}

/**
 * Which measurement a recording comes from (V-18): the day of the current measurement when every recorded run is one of
 * its runs, else the day the recording was made, named as earlier than the current measurement; nothing while the
 * current measurement is still being read.
 */
function recordingDay(
  t: TFunction,
  scenes: readonly Scene[],
  cases: readonly { readonly isPending: boolean; readonly data?: MeasuredCase | undefined }[],
): string | null {
  if (scenes.some((_, index) => cases[index]?.isPending ?? true)) {
    return null;
  }
  const days = scenes.map((scene, index) => startedDay(scene.runId, cases[index]?.data));
  if (days.every((day) => day !== null)) {
    return t('space.r7.replay.measured', { date: [...new Set(days)].join(', ') });
  }
  const made = scenes[0]?.recordedAt?.slice(0, 10) ?? null;
  return made ? t('space.r7.replay.earlier', { date: made }) : null;
}

/** The day of the current measurement's middle run a situation without a recording shows. */
function measuredDay(t: TFunction, middle: string | null, measured: MeasuredCase | undefined): string | null {
  const day = startedDay(middle, measured);
  return day ? t('space.r7.replay.measured', { date: day }) : null;
}

function repeatLine(
  t: TFunction,
  runs: number,
  same: number,
  passedAfterCheck: number,
  normal: boolean,
): string {
  if (normal && passedAfterCheck > 0) {
    return t('space.r7.replay.repeat.afterCheck', { runs, n: passedAfterCheck });
  }
  return same === runs
    ? t('space.r7.replay.repeat.same', { runs })
    : t('space.r7.replay.repeat.some', { runs, same });
}

/** What the situation should get, set in advance from the company's work records (the run's own score). */
function expectedKey(classification: string | null): string {
  return classification === 'THREAT'
    ? 'space.r7.replay.expected.THREAT'
    : classification === 'NORMAL'
      ? 'space.r7.replay.expected.NORMAL'
      : 'space.r7.replay.expected.none';
}

/** The two recorded runs side by side, as screen 2-3 shows the two tries. */
function PairTable({ columns }: { readonly columns: readonly Column[] }) {
  const { t } = useTranslation();
  return (
    <table className={results.results} data-cases="two">
      <thead>
        <tr>
          <th scope="col">{t('e1.result.table.approach')}</th>
          {columns.map((column) => (
            <th key={column.runId} scope="col">
              {column.name}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {CONTROL_ORDER.map((control) => (
          <tr key={control} data-contexa={control === 'D' || undefined}>
            <th scope="row">{t(`control.${control}.name`)}</th>
            {columns.map((column) => (
              <td key={column.runId} data-label={column.name}>
                <ResultCell score={column.score} control={control} />
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** One stored run: each approach's result and the records that went out, as screen 1-4 shows a try. */
function RunTable({ column }: { readonly column: Column }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  return (
    <table className={results.results}>
      <thead>
        <tr>
          <th scope="col">{t('e1.result.table.approach')}</th>
          <th scope="col">{t('e1.result.table.result')}</th>
          <th scope="col">{t('e1.result.table.out')}</th>
        </tr>
      </thead>
      <tbody>
        {CONTROL_ORDER.map((control) => {
          const business = column.score.business[control];
          return (
            <tr key={control} data-contexa={control === 'D' || undefined}>
              <th scope="row">{t(`control.${control}.name`)}</th>
              <td>
                <ResultCell score={column.score} control={control} />
              </td>
              <td className={results.items} data-label={t('e1.result.table.out')}>
                {business ? t('e1.result.items', { items: count(business.exposedItems, language) }) : '-'}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** Contexa's judgment of a one-request run, as the server scored it; none for a longer run or no judgment. */
function scoredVerdict(score: RunScore): Verdict | null {
  if (score.executedSteps !== 1) {
    return null;
  }
  const judged = score.verdicts.find((entry) => entry.score.stepNo === 1)?.score ?? null;
  if (
    judged === null ||
    judged.result === 'UNRESOLVED' ||
    judged.finalAction === null ||
    !(judged.finalAction in VERDICTS)
  ) {
    return null;
  }
  return judged.finalAction as Verdict;
}

/** One approach's result: Contexa's judgment chip where it judged, then the scored result in plain words. */
function ResultCell({ score, control }: { readonly score: RunScore; readonly control: ControlId }) {
  const { t } = useTranslation();
  const result = score.business[control]?.result ?? null;
  const verdict = control === 'D' ? scoredVerdict(score) : null;
  const wordKey = result ? RESULT_WORDS[result] : undefined;
  return (
    <span className={results.cell}>
      {verdict ? <VerdictChip verdict={verdict} /> : null}
      {wordKey ? (
        <span className={results.word} data-wrong={score.correct[control] === false || undefined}>
          {t(wordKey)}
        </span>
      ) : verdict ? null : (
        <span className={results.word}>-</span>
      )}
    </span>
  );
}

/**
 * The "see details" of the table (R-2): one chip for one run; for a pair, one per run, each naming whose run it opens,
 * in the same look as the frame's chip.
 */
function DetailButtons({ columns }: { readonly columns: readonly Column[] }) {
  const { t } = useTranslation();
  const detail = useDetail();
  const [only] = columns;
  if (columns.length === 1 && only) {
    return <DetailChip runId={only.runId} step={1} />;
  }
  return (
    // One group of the same action, one block for the spacing check (the two wrap on phones).
    <div className={styles.details} data-block>
      {columns.map((column) => (
        <button
          key={column.runId}
          type="button"
          className={chip.detail}
          onClick={() => detail.show(column.runId, 1)}
        >
          <Icon name="search" className={chip.detailIcon} />
          {t('space.r7.replay.detailOf', { who: column.name })}
        </button>
      ))}
    </div>
  );
}
