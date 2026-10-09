import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useLabOptions, useRecentLabRuns, useStepResult, useVersus, type VersusSide } from '../../api/lab';
import type { StepResult } from '../../api/types';
import { AssessPanel } from '../../components/assessment/AssessPanel';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { useDetail } from '../../components/detail/useDetail';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER, OUTCOME_KEYS, type BusinessOutcome } from '../../domain/verdict';
import { count } from '../../journey/format';
import { verdictKey } from '../try/steps/liveRun';
import { LabScreen } from './LabScreen';
import styles from './LabPages.module.css';

/** One run's reasons as the engine recorded them: the contract sentence in plain words, or the model's own words. */
function Reason({ label, result }: { readonly label: string; readonly result: StepResult | null }) {
  const { t } = useTranslation();
  const reason = result?.engineReason ?? null;
  return (
    <section className={styles.reason}>
      <h3 className={styles.reasonLabel}>{label}</h3>
      {reason?.canonical ? (
        <p>
          {t(`reason.canonical.${reason.canonical}`, { defaultValue: reason.reasoning ?? '' })}
          <span className={styles.ruleSet}>{t('labResult.ruleSet')}</span>
        </p>
      ) : reason?.reasoning ? (
        <p>
          {t('labResult.modelWrote')} <span data-original>{reason.reasoning}</span>
        </p>
      ) : (
        <p>{t('labResult.noReason')}</p>
      )}
    </section>
  );
}

/**
 * L3, the result and the reasons compared (lab-3, 7.6): whether the one changed condition changed Contexa's decision
 * (the server compares the runs), every approach before and now with the changed ones marked, what the engine received
 * differently, the visitor's call against the right answer, and both runs' reasons. Without a previous run of the case
 * only this run is shown.
 */
/**
 * The headline when Contexa's answer changed (lab-3, plan 7.0 "only the approval changed …"): the changed conditions
 * as the server compared the two runs' stored compositions; the plain form when either run was not a lab run.
 */
function changedHeadline(
  t: ReturnType<typeof useTranslation>['t'],
  conditions: readonly string[] | null,
  verdicts: { readonly from: string; readonly to: string },
): string {
  if (conditions === null) {
    return t('labResult.changed', verdicts);
  }
  if (conditions.length === 0) {
    return t('labResult.changedSame', verdicts);
  }
  if (conditions.length === 1) {
    const name = conditions[0] ?? '';
    return t('labResult.changedOne', { ...verdicts, condition: t(`lab.fieldInline.${name}`, { defaultValue: name }) });
  }
  return t('labResult.changedMany', { ...verdicts, n: conditions.length });
}

export default function LabResultPage() {
  const { t, i18n } = useTranslation();
  const detail = useDetail();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params] = useSearchParams();
  const runId = params.get('run');
  const against = params.get('against');
  const options = useLabOptions().data ?? null;
  // Without a previous run the server reads this run against itself, so every value is still the server's.
  const compared = useVersus(runId, against ?? runId).data ?? null;
  const versus = against ? compared : null;
  const recent = useRecentLabRuns().data ?? [];
  const mine = recent.find((entry) => entry.runId === runId) ?? null;
  const nowResult = useStepResult(runId, 1).data ?? null;
  const beforeResult = useStepResult(against, 1).data ?? null;
  const assess = useUrlModal('assess');
  const caseKey = mine?.caseKey ?? compared?.now.scenarioKey ?? null;
  const labCase = options?.cases.find((candidate) => candidate.key === caseKey) ?? null;

  if (!runId) {
    return (
      <LabScreen
        step="send"
        title={t('labResult.title')}
        purpose={t('labResult.noRun')}
        back={{ to: '/lab/case', label: t('labChange.back') }}
      >
        {null}
      </LabScreen>
    );
  }
  if (!compared) {
    return <StateScreen kind="loading" />;
  }
  const nowSide: VersusSide = compared.now;
  const verdict = (action: string | null) => t(verdictKey(action ?? 'NONE'));
  const outcomeText = (outcome: string | undefined) =>
    outcome && outcome in OUTCOME_KEYS ? t(OUTCOME_KEYS[outcome as BusinessOutcome]) : '-';
  const headline = versus
    ? versus.contexaChanged
      ? changedHeadline(t, versus.changedConditions, {
          from: verdict(versus.before.engineAction),
          to: verdict(versus.now.engineAction),
        })
      : t('labResult.same', { verdict: verdict(versus.now.engineAction) })
    : t('labResult.only', { verdict: verdict(nowSide.engineAction) });
  const answer = mine?.designed
    ? labCase?.classification === 'THREAT'
      ? 'stop'
      : labCase?.classification === 'NORMAL'
        ? 'pass'
        : 'none'
    : 'none';
  return (
    <LabScreen
      step="send"
      title={headline}
      purpose={versus ? t('labResult.purpose') : t('labResult.purposeOnly')}
      source={
        <SourceMark kind="ENGINE" runId={runId} step={1}>
          {versus
            ? t('labResult.source', { before: against ?? '-', now: runId })
            : t('labResult.sourceOnly', { now: runId })}
        </SourceMark>
      }
      back={{ to: '/lab/case', label: t('labResult.back') }}
      more={
        <>
          <ActionChip onClick={() => detail.show(runId)} icon="search" variant="open">
            {t('labResult.detail')}
          </ActionChip>
          <ActionChip icon="check" variant="open" onClick={() => assess.show()}>
            {t('labResult.assess')}
          </ActionChip>
        </>
      }
      main={
        caseKey ? (
          <NextLink to={`/lab/change?case=${encodeURIComponent(caseKey)}`} label={t('labResult.next')} />
        ) : null
      }
    >
      <table className={styles.versus}>
        <caption className={styles.caption}>{t('labResult.caption')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('labResult.col.approach')}</th>
            {versus ? <th scope="col">{t('labResult.col.before')}</th> : null}
            <th scope="col">{t('labResult.col.now')}</th>
          </tr>
        </thead>
        <tbody>
          {CONTROL_ORDER.map((control) => {
            const changed = versus?.changedControls.includes(control) ?? false;
            return (
              <tr key={control} data-changed={changed || undefined}>
                <th scope="row">{t(`control.${control}.name`)}</th>
                {versus ? <td>{outcomeText(versus.before.outcomes[control])}</td> : null}
                <td>
                  {outcomeText(nowSide.outcomes[control])}
                  {changed ? <span className={styles.changedTag}>{t('labResult.changedTag')}</span> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className={styles.note}>
        {t('labResult.exposed', { items: count(nowSide.exposedItems, language) })}
      </p>
      {versus && versus.inputs.length > 0 ? (
        <section className={styles.panel} aria-labelledby="lab-inputs">
          <h2 id="lab-inputs" className={styles.panelTitle}>
            {t('labResult.inputs')}
          </h2>
          <ul className={styles.inputs}>
            {versus.inputs.map((input) => (
              <li key={input.key}>
                <code data-original>
                  {input.key}: {input.before ?? '-'} → {input.now ?? '-'}
                </code>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      <dl className={styles.callLine}>
        <div>
          <dt>{t('labResult.yourCall')}</dt>
          <dd>{mine?.call ? t(`labSend.calls.${mine.call}`) : t('labResult.noCall')}</dd>
        </div>
        <div>
          <dt>{t('labResult.rightAnswer')}</dt>
          <dd>{t(`labCase.answer.${answer}`)}</dd>
        </div>
      </dl>
      <div className={styles.reasons}>
        {versus ? <Reason label={t('labResult.reasonBefore')} result={beforeResult} /> : null}
        <Reason label={t('labResult.reasonNow')} result={nowResult} />
      </div>
      <Modal open={assess.open} onClose={assess.hide} title={t('labResult.assess')}>
        <AssessPanel runId={runId} reasons={options?.assessmentReasons ?? []} />
      </Modal>
    </LabScreen>
  );
}
