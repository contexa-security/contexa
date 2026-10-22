import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useHook } from '../../../api/hook';
import { useJourney, type PredictionScore } from '../../../api/journey';
import type { LabCase } from '../../../api/lab';
import { useRunScore } from '../../../api/queries';
import type { CaseResult, RunScore } from '../../../api/types';
import { DetailChip, SourceLine } from '../../../components/journey/FrameParts';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { NextLink } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { VerdictChip } from '../../../components/VerdictChip';
import { CONTROL_ORDER, VERDICTS, type ControlId, type Verdict } from '../../../domain/verdict';
import { count } from '../../../journey/format';
import type { Difference } from '../../../journey/journey';
import { useJourneyPlace } from '../../../journey/useJourneyPlace';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from './ResultStep.module.css';
import { useTryAnalysis, useTryRun } from './tryRun';

/**
 * The plain word of each scored result (화면재편-기획안 11.2): what the approach did, said as right or as the kind of
 * wrong it was. NOT_SCORED has none; its cell shows what the record has.
 */
const RESULT_WORDS: Readonly<Partial<Record<CaseResult, string>>> = {
  STOPPED: 'p1.result.word.STOPPED',
  PARTLY_STOPPED: 'p1.result.word.PARTLY_STOPPED',
  MISSED: 'p1.result.word.MISSED',
  PASSED: 'p1.result.word.PASSED',
  PASSED_AFTER_CHECK: 'p1.result.word.PASSED_AFTER_CHECK',
  HALTED: 'p1.result.word.HALTED',
  UNRESOLVED: 'p1.result.word.UNRESOLVED',
};

/** The judgments a stopping headline names; any other stop is said without the judgment. */
const STOPPING_ACTIONS = new Set(['BLOCK', 'CHALLENGE', 'ESCALATE']);

interface ResultStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Screens 1-4 and 2-3, the result (T5): the one sentence the server's results pick as the title, the visitor's
 * prediction in one line under it as the server compared it, and one table of the five approaches. Every cell is the
 * server's score of the run: Contexa's judgment, and each approach's result in plain words.
 */
export function ResultStep({ role, mode, labCase, see, flow }: ResultStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const number = useJourneyPlace().screen?.number ?? (role === 'attacker' ? '1-4' : '2-3');
  const run = useTryRun(labCase.key, labCase.requests.length);
  const runId = run.runId;
  const score = useRunScore(runId, runId ? 'result' : null, 1).data ?? null;
  const decision = useTryAnalysis(run.view, run.stored).decision;
  const journey = useJourney();
  const call = journey.data?.predictions.find((prediction) => prediction.caseKey === labCase.key) ?? null;

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!runId) {
    return (
      <ScreenBody
        title={t('p1.result.empty')}
        purpose={t('p1.notSent')}
        back={flow.back}
        main={<NextLink to={stepPath(role, 'predict', mode)} label={t('p1.toPredict')} />}
      >
        {null}
      </ScreenBody>
    );
  }
  if (!score) {
    return <StateScreen kind="loading" />;
  }

  if (role === 'owner') {
    return <OwnerResult number={number} runId={runId} score={score} call={call} see={see} flow={flow} />;
  }

  const contexa = score.business.D;
  const engineAction = decision?.finalAction ?? score.verdicts[0]?.score.finalAction ?? null;
  const headlineKey =
    contexa.result === 'STOPPED'
      ? `e1.result.headline.STOPPED.${engineAction && STOPPING_ACTIONS.has(engineAction) ? engineAction : 'other'}`
      : contexa.result === 'PARTLY_STOPPED' || contexa.result === 'MISSED'
        ? `e1.result.headline.${contexa.result}`
        : 'e1.result.headline.other';

  return (
    <ScreenBody
      title={t(headlineKey, { items: count(contexa.exposedItems, language) })}
      purpose={t(`screen.${number}.guide`)}
      more={<DetailChip runId={runId} step={1} />}
      sourceLine={<SourceLine kind="run" runId={runId} />}
      back={flow.back}
      main={flow.next}
    >
      <PredictionLine call={call} runId={runId} />
      <table className={styles.results}>
        <thead>
          <tr>
            <th scope="col">{t('e1.result.table.approach')}</th>
            <th scope="col">{t('e1.result.table.result')}</th>
            <th scope="col">{t('e1.result.table.out')}</th>
          </tr>
        </thead>
        <tbody>
          {CONTROL_ORDER.map((control) => {
            const business = score.business[control];
            return (
              <tr key={control} data-contexa={control === 'D' || undefined}>
                <th scope="row">{t(`control.${control}.name`)}</th>
                <td>
                  <ResultCell score={score} control={control} />
                </td>
                <td className={styles.items} data-label={t('e1.result.table.out')}>
                  {business ? t('e1.result.items', { items: count(business.exposedItems, language) }) : '-'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </ScreenBody>
  );
}

/** Contexa's judgment of the run's first request as the server scored it; null when it made none. */
function scoredVerdict(score: RunScore): { readonly verdict: Verdict; readonly unresolved: boolean } | null {
  const judged = score.verdicts.find((entry) => entry.score.stepNo === 1)?.score ?? null;
  if (judged === null || judged.finalAction === null || !(judged.finalAction in VERDICTS)) {
    return null;
  }
  return { verdict: judged.finalAction as Verdict, unresolved: judged.result === 'UNRESOLVED' };
}

/**
 * One approach's result cell: Contexa's judgment chip where it judged, then the scored result in plain words; a
 * result the server scored as wrong is marked, by word and color together.
 */
function ResultCell({ score, control }: { readonly score: RunScore; readonly control: ControlId }) {
  const { t } = useTranslation();
  const result = score.business[control]?.result ?? null;
  const judged = control === 'D' ? scoredVerdict(score) : null;
  // A failed judgment is said once, by the word.
  const chip = judged && !judged.unresolved ? judged.verdict : null;
  const wordKey = result ? RESULT_WORDS[result] : undefined;
  return (
    <span className={styles.cell}>
      {chip ? <VerdictChip verdict={chip} /> : null}
      {wordKey ? (
        <span className={styles.word} data-wrong={score.correct[control] === false || undefined}>
          {t(wordKey)}
        </span>
      ) : chip ? null : (
        <span className={styles.word}>-</span>
      )}
    </span>
  );
}

/**
 * The visitor's prediction in one line (F-5): the pick, then the sentence the server's comparison picks. The same
 * judgment, a different judgment that still keeps the data in, or a different handling. Nothing shows before the
 * server has compared the pick with this very run.
 */
function PredictionLine({ call, runId }: { readonly call: PredictionScore | null; readonly runId: string }) {
  const { t } = useTranslation();
  const engine = call?.call.engine ?? null;
  if (
    call === null ||
    engine === null ||
    call.runId !== runId ||
    call.engineSameAction === null ||
    call.engineSameStop === null
  ) {
    return null;
  }
  const sentence = call.engineSameAction
    ? 'p1.result.mine.same'
    : call.engineSameStop
      ? 'p1.result.mine.sameStop'
      : 'p1.result.mine.other';
  return (
    <p className={styles.mine}>
      <span className={styles.mineLabel}>{t('p1.result.mine.label')}</span>
      <VerdictChip verdict={engine} />
      <span>{t(sentence)}</span>
    </p>
  );
}

/** Try 2 headline, chosen from the record: Contexa result first, then the time and volume limits' result (2-3). */
function ownerHeadline(score: RunScore): string {
  const contexa = score.business.D.result;
  if (contexa === 'PASSED') {
    return score.business.C1.result === 'HALTED'
      ? 'e2.result.headline.PASSED_RULE_HALTED'
      : 'e2.result.headline.PASSED_RULE_PASSED';
  }
  if (contexa === 'PASSED_AFTER_CHECK' || contexa === 'HALTED') {
    return `e2.result.headline.${contexa}`;
  }
  return 'e2.result.headline.other';
}

interface OwnerResultProps {
  readonly number: string;
  readonly runId: string;
  readonly score: RunScore;
  readonly call: PredictionScore | null;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Screen 2-3: the same request by the person with a stolen account and by the real employee, as one table side by
 * side, every cell the server's score of that run. The first case is the visitor's own run of it, or the recorded run
 * the first screen shows when they skipped it, which the column says.
 */
function OwnerResult({ number, runId, score, call, see, flow }: OwnerResultProps) {
  const { t } = useTranslation();
  const journey = useJourney();
  const hook = useHook();
  const own =
    journey.data?.runs.find((line) => line.scenarioKey === 'A3' && line.status === 'COMPLETED') ?? null;
  const firstRunId = own?.runId ?? hook.data?.attacker.runId ?? null;
  const first = useRunScore(firstRunId, firstRunId ? 'result' : null, 1).data ?? null;
  const contexa = score.business.D.result;
  const shown =
    score.business.C1.result === 'HALTED' && (contexa === 'PASSED' || contexa === 'PASSED_AFTER_CHECK');

  useEffect(() => {
    if (shown) {
      see(3);
    }
    // Seen once the record shows it; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shown]);

  const attacker = t(own ? 'p2.result.table.attacker' : 'p2.result.table.attackerRecord');
  const owner = t('p2.result.table.owner');

  return (
    <ScreenBody
      title={t(ownerHeadline(score))}
      purpose={t(`screen.${number}.guide`)}
      more={<DetailChip runId={runId} step={1} />}
      sourceLine={<SourceLine kind="run" runId={runId} />}
      back={flow.back}
      main={flow.next}
    >
      <PredictionLine call={call} runId={runId} />
      <table className={styles.results} data-cases="two">
        <thead>
          <tr>
            <th scope="col">{t('e1.result.table.approach')}</th>
            <th scope="col">{attacker}</th>
            <th scope="col">{owner}</th>
          </tr>
        </thead>
        <tbody>
          {CONTROL_ORDER.map((control) => (
            <tr key={control} data-contexa={control === 'D' || undefined}>
              <th scope="row">{t(`control.${control}.name`)}</th>
              <td data-label={attacker}>{first ? <ResultCell score={first} control={control} /> : '-'}</td>
              <td data-label={owner}>
                <ResultCell score={score} control={control} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </ScreenBody>
  );
}
