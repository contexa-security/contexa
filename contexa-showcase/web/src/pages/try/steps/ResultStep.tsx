import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useCases } from '../../../api/anatomy';
import { useHook } from '../../../api/hook';
import { useJourney, type PredictionScore } from '../../../api/journey';
import { useStepResult, type LabCase } from '../../../api/lab';
import { useMeasuredCase, type MeasuredCase } from '../../../api/measured';
import { useRunScore } from '../../../api/queries';
import type { RunScore } from '../../../api/types';
import { ActionChip } from '../../../components/common/ActionChip';
import { useDetail } from '../../../components/detail/useDetail';
import { JustSaw } from '../../../components/journey/JourneyParts';
import { SourceMark } from '../../../components/common/SourceMark';
import { ActionBar, MoreRow, RightMark, StepHeader } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { CONTROL_ORDER } from '../../../domain/verdict';
import { count, seconds } from '../../../journey/format';
import type { Difference } from '../../../journey/journey';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from '../Experience.module.css';
import { useTryAnalysis, useTryRun } from './tryRun';

const ENGINE_ACTION_KEYS: Readonly<Record<string, string>> = {
  ALLOW: 'e1.predict.ALLOW',
  CHALLENGE: 'e1.predict.CHALLENGE',
  ESCALATE: 'e1.predict.ESCALATE',
  BLOCK: 'e1.predict.BLOCK',
};

interface ResultStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Try 1-5, the result (e1-result): who answered right, the five approaches and the visitor. The headline is the one the
 * server's result codes pick, every approach is scored against the right answer by the one scoring rule, Contexa's row
 * carries the same conditions measured several times, and the visitor's call is the server's score of it. The case's
 * reason for the right answer is folded (D-41).
 */
export function ResultStep({ role, mode, labCase, see, flow }: ResultStepProps) {
  const { t, i18n } = useTranslation();
  const detail = useDetail();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view = run.view;
  const runId = run.runId;
  const score = useRunScore(runId, runId ? 'result' : null, 1).data ?? null;
  const step = useStepResult(runId, 1).data ?? null;
  const decision = useTryAnalysis(view, run.stored).decision;
  const journey = useJourney();
  const cases = useCases();
  const measured = useMeasuredCase(labCase.key).data ?? null;

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!runId) {
    return (
      <>
        <StepHeader title={t('experience.step.result')} purpose={t('e1.run.notSent')} />
        <ActionBar back={{ to: stepPath(role, 'predict', mode), label: t('e1.run.toPredict') }} />
      </>
    );
  }
  if (!score || !step) {
    return <StateScreen kind="loading" />;
  }

  if (role === 'owner') {
    return (
      <OwnerResult
        labCase={labCase}
        runId={runId}
        score={score}
        measured={measured}
        call={journey.data?.predictions.find((prediction) => prediction.caseKey === labCase.key) ?? null}
        rationale={
          cases.data?.cases.find((candidate) => candidate.key === labCase.key)?.rationale[language] ?? null
        }
        see={see}
        flow={flow}
      />
    );
  }

  const contexa = score.business.D;
  const engineAction = decision?.finalAction ?? score.verdicts[0]?.score.finalAction ?? null;
  const analysisMs = decision?.totalAnalysisMs ?? null;
  const headlineKey =
    contexa.result === 'STOPPED'
      ? `e1.result.headline.STOPPED.${engineAction && engineAction !== 'ALLOW' ? engineAction : 'other'}`
      : contexa.result === 'PARTLY_STOPPED' || contexa.result === 'MISSED'
        ? `e1.result.headline.${contexa.result}`
        : 'e1.result.headline.other';
  const caseView = cases.data?.cases.find((candidate) => candidate.key === labCase.key) ?? null;
  const call = journey.data?.predictions.find((prediction) => prediction.caseKey === labCase.key) ?? null;
  const rulesStopped = score.business.C1.result === 'STOPPED' && score.business.C2.result === 'STOPPED';
  const layers = new Map(step.layers.map((layer) => [layer.control, layer]));
  const threat = labCase.classification === 'THREAT';

  return (
    <>
      <StepHeader
        title={t(headlineKey, {
          seconds: analysisMs === null ? '-' : seconds(analysisMs),
          items: count(contexa.exposedItems, language),
        })}
        purpose={t(threat ? 'e1.purpose.result.THREAT' : 'e1.purpose.result.NORMAL')}
        source={
          <SourceMark kind="ENGINE" runId={runId} step={1}>
            {measured ? t('e1.result.sourceMeasured', { protocol: measured.protocolId }) : null}
          </SourceMark>
        }
      />
      <table className={styles.results}>
        <thead>
          <tr>
            <th scope="col">{t('e1.result.table.approach')}</th>
            <th scope="col">{t('e1.result.table.result')}</th>
            <th scope="col">{t('e1.result.table.out')}</th>
            <th scope="col">{t('e1.result.table.right')}</th>
          </tr>
        </thead>
        <tbody>
          {CONTROL_ORDER.map((control) => {
            const layer = layers.get(control);
            return (
              <tr key={control} data-contexa={control === 'D' || undefined}>
                <th scope="row">{controlName(t, control)}</th>
                <td>
                  <span className={styles.resultValue}>
                    {!layer
                      ? '-'
                      : control === 'D' && layer.verdict
                        ? t(`verdict.${verdictWord(layer.verdict)}`)
                        : layer.outcome === 'DELIVERED'
                          ? t('e1.result.allowed')
                          : t('e1.result.denied', {
                              rule: layer.ruleId
                                ? t(`ruleId.${layer.ruleId}`, { defaultValue: layer.ruleId })
                                : '-',
                            })}
                  </span>
                  {control === 'D' && measured ? (
                    <span className={styles.resultMeasured}>{measuredText(t, language, measured)}</span>
                  ) : null}
                </td>
                <td>
                  {t('e1.result.items', { items: count(score.business[control].exposedItems, language) })}
                </td>
                <td>
                  <RightMark right={score.correct[control]} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className={styles.tableNote}>
        {role === 'attacker' && rulesStopped ? <p>{t('e1.result.rulesToo')}</p> : null}
        <p>{t('hook.note')}</p>
      </div>
      <div className={styles.mine}>
        <p className={styles.mineLine}>
          <span className={styles.mineLabel}>{t('e1.result.mineLabel')}</span>
          {call?.call.engine ? (
            <>
              <strong>{t(ENGINE_ACTION_KEYS[call.call.engine] ?? call.call.engine)}</strong>
              <RightMark right={call.engineRight} />
            </>
          ) : (
            <span>{t('e1.result.mineNoneShort')}</span>
          )}
          <span className={styles.mineAnswer}>
            {t('e1.result.answerShort', {
              actions: score.truth.allowedEngineActions
                .map((action) => t(ENGINE_ACTION_KEYS[action] ?? action))
                .join(t('e1.result.or')),
            })}
          </span>
        </p>
        {call?.call.existing && call.existingActual ? (
          <p className={styles.mineLine}>
            <span className={styles.mineLabel}>{t('e1.result.existingLabel')}</span>
            {t('e1.result.existingShort', {
              call: t(`e1.predict.existing.${call.call.existing}`),
              actual: t(`e1.predict.existing.${call.existingActual}`),
            })}
          </p>
        ) : null}
      </div>
      <MoreRow>
        {caseView?.rationale[language] ? (
          <details className={styles.more}>
            <summary>{t('e1.result.rationaleOpen')}</summary>
            <p className={styles.foldText}>
              {caseView.rationale[language]}
              <SourceMark kind="CASE">{labCase.key}</SourceMark>
            </p>
          </details>
        ) : null}
        <ActionChip onClick={() => detail.show(runId)} icon="search" variant="open">
          {t('e1.result.detail')}
        </ActionChip>
      </MoreRow>
      <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
    </>
  );
}

/** An approach's name; the business record rule carries "*", the mark of a rule written for these cases (3절). */
function controlName(t: ReturnType<typeof useTranslation>['t'], control: string): string {
  return control === 'C2' ? `${t('control.C2.name')}*` : t(`control.${control}.name`);
}

/** The same conditions measured several times (V-17): every value is the portal's count of the measurement. */
function measuredText(
  t: ReturnType<typeof useTranslation>['t'],
  language: string,
  measured: MeasuredCase,
): string {
  const range = measured.analysisMs;
  const items = measured.exposedItems;
  const itemsText =
    items === null
      ? '-'
      : items.min === items.max
        ? count(items.min, language)
        : `${count(items.min, language)}~${count(items.max, language)}`;
  if (!measured.allSame) {
    return t('e1.result.measuredMixed', {
      runs: measured.runs,
      results: Object.entries(measured.results)
        .map(([result, n]) =>
          t('measured.times', { result: t(`measured.${result}`, { defaultValue: result }), n }),
        )
        .join(' · '),
    });
  }
  return range === null || range.min === range.max
    ? t('e1.result.measuredOne', {
        runs: measured.runs,
        from: range === null ? '-' : seconds(range.min),
        items: itemsText,
      })
    : t('e1.result.measured', {
        runs: measured.runs,
        from: seconds(range.min),
        to: seconds(range.max),
        items: itemsText,
      });
}

function verdictWord(verdict: NonNullable<RunScore['verdicts'][number]['score']['finalAction']>): string {
  switch (verdict) {
    case 'ALLOW':
      return 'allow';
    case 'CHALLENGE':
      return 'verify';
    case 'ESCALATE':
      return 'review';
    case 'BLOCK':
      return 'block';
    default:
      return 'none';
  }
}

/** Try 2 headline, chosen from the record: Contexa result first, then the threshold rule result (e2-result). */
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
  readonly labCase: LabCase;
  readonly runId: string;
  readonly score: RunScore;
  readonly measured: MeasuredCase | null;
  readonly call: PredictionScore | null;
  readonly rationale: string | null;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Try 2-5, the result (e2-result): the same request with the opposite right answer, as one table of the two tries
 * side by side, every cell the server score of that run. Try 1 is the visitor own run of it, or the designated measured
 * run when they skipped it, which the column says. The business record rule note shows only when it answered both
 * right, and "just seen 3" only when the record says what it states.
 */
function OwnerResult({ labCase, runId, score, measured, call, rationale, see, flow }: OwnerResultProps) {
  const { t, i18n } = useTranslation();
  const detail = useDetail();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const journey = useJourney();
  const hook = useHook();
  const own =
    journey.data?.runs.find((line) => line.scenarioKey === 'A3' && line.status === 'COMPLETED') ?? null;
  const firstRunId = own?.runId ?? hook.data?.attacker.runId ?? null;
  const first = useRunScore(firstRunId, firstRunId ? 'result' : null, 1).data ?? null;
  const contexa = score.business.D.result;
  const shown =
    score.business.C1.result === 'HALTED' && (contexa === 'PASSED' || contexa === 'PASSED_AFTER_CHECK');
  const recordsBoth = first !== null && first.correct.C2 === true && score.correct.C2 === true;

  useEffect(() => {
    if (shown) {
      see(3);
    }
    // Seen once the record shows it; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shown]);

  const cell = (result: string | undefined, right: boolean | undefined) => (
    <span className={styles.tryCell}>
      <span>
        {result
          ? t(result === 'HALTED' ? 'e2.result.halted' : `measured.${result}`, { defaultValue: result })
          : '-'}
      </span>
      <RightMark right={right} />
    </span>
  );

  return (
    <>
      <StepHeader
        title={t(ownerHeadline(score))}
        purpose={t('e2.purpose.result')}
        source={
          <SourceMark kind="ENGINE" runId={runId} step={1}>
            {measured ? t('e1.result.sourceMeasured', { protocol: measured.protocolId }) : null}
          </SourceMark>
        }
      />
      <table className={styles.results} data-tries="two">
        <thead>
          <tr>
            <th scope="col">{t('e1.result.table.approach')}</th>
            <th scope="col">{t(own ? 'e2.result.table.try1' : 'e2.result.table.try1Measured')}</th>
            <th scope="col">{t('e2.result.table.try2')}</th>
          </tr>
        </thead>
        <tbody>
          {CONTROL_ORDER.map((control) => (
            <tr key={control} data-contexa={control === 'D' || undefined}>
              <th scope="row">{controlName(t, control)}</th>
              <td data-label={t(own ? 'e2.result.table.try1' : 'e2.result.table.try1Measured')}>
                {first ? cell(first.business[control]?.result, first.correct[control]) : '-'}
              </td>
              <td data-label={t('e2.result.table.try2')}>
                {cell(score.business[control]?.result, score.correct[control])}
                {control === 'D' && measured ? (
                  <span className={styles.resultMeasured}>{measuredText(t, language, measured)}</span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className={styles.tableNote}>
        <p>{t(recordsBoth ? 'e2.result.recordsToo' : 'hook.note')}</p>
      </div>
      <div className={styles.mine}>
        <p className={styles.mineLine}>
          <span className={styles.mineLabel}>{t('e1.result.mineLabel')}</span>
          {call?.call.engine ? (
            <>
              <strong>{t(ENGINE_ACTION_KEYS[call.call.engine] ?? call.call.engine)}</strong>
              <RightMark right={call.engineRight} />
            </>
          ) : (
            <span>{t('e1.result.mineNoneShort')}</span>
          )}
          <span className={styles.mineAnswer}>
            {t('e1.result.answerShort', {
              actions: score.truth.allowedEngineActions
                .map((action) => t(ENGINE_ACTION_KEYS[action] ?? action))
                .join(t('e1.result.or')),
            })}
          </span>
        </p>
        {call?.call.numberRule && call.numberRuleActual ? (
          <p className={styles.mineLine}>
            <span className={styles.mineLabel}>{t('e2.result.numberLabel')}</span>
            {t('e2.result.numberShort', {
              call: t(`e2.predict.numberRule.${call.call.numberRule}`),
              actual: t(`e2.predict.numberRule.${call.numberRuleActual}`),
            })}
          </p>
        ) : null}
      </div>
      <MoreRow>
        {rationale ? (
          <details className={styles.more}>
            <summary>{t('e1.result.rationaleOpen')}</summary>
            <p className={styles.foldText}>
              {rationale}
              <SourceMark kind="CASE">{labCase.key}</SourceMark>
            </p>
          </details>
        ) : null}
        <ActionChip onClick={() => detail.show(runId)} icon="search" variant="open">
          {t('e1.result.detail')}
        </ActionChip>
      </MoreRow>
      {shown ? <JustSaw difference={3} sentence="e2Result" /> : null}
      <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
    </>
  );
}
