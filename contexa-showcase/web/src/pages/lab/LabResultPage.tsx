import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useLabOptions, useRecentLabRuns, useVersus, type VersusSide } from '../../api/lab';
import { useLabDelta, type LabDelta } from '../../api/promptQuality';
import { AssessPanel } from '../../components/assessment/AssessPanel';
import { Modal } from '../../components/common/Modal';
import { useUrlModal } from '../../components/common/useUrlModal';
import { Icon } from '../../components/Icon';
import { DetailChip, SourceLine } from '../../components/journey/FrameParts';
import { NextLink } from '../../components/journey/StepParts';
import { Chip } from '../../components/main/Chip';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER } from '../../domain/verdict';
import { count } from '../../journey/format';
import { isScored, resultChip, type ChipKind } from '../main/mainCases';
import { verdictKey } from '../try/steps/liveRun';
import { LabScreen } from './LabScreen';
import { expectationOf } from './labPlace';
import styles from './LabScreens.module.css';

/**
 * The title when Contexa's judgment changed (lab-3): the changed conditions as the server compared the two runs' stored
 * compositions; the plain form when either run was not a lab run.
 */
function changedHeadline(
  t: TFunction,
  conditions: readonly string[] | null,
  verdicts: { readonly from: string; readonly to: string },
): string {
  if (conditions === null) {
    return t('lab.r7.result.headline.changed', verdicts);
  }
  if (conditions.length === 0) {
    return t('lab.r7.result.headline.changedSame', verdicts);
  }
  if (conditions.length === 1) {
    const name = conditions[0] ?? '';
    return t('lab.r7.result.headline.changedOne', {
      ...verdicts,
      condition: t(`lab.fieldInline.${name}`, { defaultValue: name }),
    });
  }
  return t('lab.r7.result.headline.changedMany', { ...verdicts, n: conditions.length });
}

/**
 * One answer as the deck's result chips (T-01, B-08), each kind in its own color: the server's business result when
 * the situation has a set handling, else what the data did (blocked, blocked after some left, allowed). Nothing is
 * judged here; a missing answer has no chip.
 */
function answerChip(
  business: string | undefined,
  outcome: string | undefined,
): { readonly key: string; readonly kind: ChipKind } | null {
  if (isScored(business)) {
    return resultChip(business);
  }
  switch (outcome) {
    case 'STOPPED':
    case 'HELD':
      // The data stayed in: the deck's "blocked" (자료가 안 나감); Contexa's cell adds what it judged.
      return { key: 'main.lane.stopped', kind: 'block' };
    case 'CUT':
      return { key: 'main.lane.cut', kind: 'auth' };
    case 'DELIVERED':
      return { key: 'main.lane.allowed', kind: 'allow' };
    case 'BROKEN':
      return { key: 'outcome.broken', kind: 'bad' };
    case 'UNRESOLVED':
      return { key: 'outcome.unresolved', kind: 'bad' };
    default:
      return null;
  }
}

/**
 * The server's check that the changed condition reached what the AI received, in one line (U-5, C-22): a request it
 * found with other lines changed too, else the first request's finding; nothing for a run sent as designed or one
 * still going. The lines themselves stay in the decision details.
 */
function deltaKey(delta: LabDelta | null): string | null {
  if (!delta) {
    return null;
  }
  if (!delta.available) {
    return delta.reason === 'DESIGNED' || delta.reason === 'NOT_COMPLETED'
      ? null
      : delta.reason === 'SEVERAL_CONDITIONS' || delta.reason === 'NO_BASE'
        ? `lab.r7.result.delta.${delta.reason}`
        : 'lab.r7.result.delta.unavailable';
  }
  const failed = delta.steps.find((step) => step.notCompared === null && !step.passed);
  const step = failed ?? delta.steps[0] ?? null;
  if (!step) {
    return null;
  }
  if (step.notCompared !== null) {
    return 'lab.r7.result.delta.notCompared';
  }
  if (!step.passed) {
    return 'lab.r7.result.delta.failed';
  }
  return step.notLookedUp
    ? 'lab.r7.result.delta.notLookedUp'
    : step.sameAsBase
      ? 'lab.r7.result.delta.sameAsBase'
      : 'lab.r7.result.delta.passed';
}

/**
 * The result compared (화면재편 R7, T5): the one sentence the server's comparison picks as the title (whether the
 * changed condition changed Contexa's judgment), the visitor's call and what is set in advance in one line, one table
 * of every approach's answer last time and this time as the deck's result chips (Contexa's with its judgment) with
 * the changed rows marked, how many records got out through
 * Contexa, and the server's check that the change reached the AI's input. The reasons, the input lines and the record
 * are in the decision details. Without an earlier run of the case only this run shows.
 */
export default function LabResultPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params] = useSearchParams();
  const runId = params.get('run');
  const against = params.get('against');
  const options = useLabOptions().data ?? null;
  const recent = useRecentLabRuns().data ?? [];
  const mine = recent.find((entry) => entry.runId === runId) ?? null;
  // Without an earlier run of the visitor the latest real run of the case sent as designed is the comparison (B-08);
  // without that either the server reads this run against itself, so every value is still the server's.
  const reference = against ? null : (mine?.referenceRunId ?? null);
  const base = against ?? reference;
  const compared = useVersus(runId, base ?? runId).data ?? null;
  const versus = base ? compared : null;
  const delta = useLabDelta(runId).data ?? null;
  const assess = useUrlModal('assess');
  const caseKey = mine?.caseKey ?? compared?.now.scenarioKey ?? null;
  const labCase = options?.cases.find((candidate) => candidate.key === caseKey) ?? null;

  if (!runId) {
    return (
      <LabScreen
        step="result"
        type="T5"
        title={t('p1.result.empty')}
        purpose={t('lab.r7.result.noRun')}
        back={{ to: '/lab/case', label: t('frame.back') }}
        main={<NextLink to="/lab/case" label={t('lab.r7.toCase')} />}
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
  // One cell: the answer's result chip, and for Contexa what it judged, so a hold that kept the data in is not read
  // as a block judgment (V-06).
  const answer = (side: VersusSide, control: string) => {
    const chip = answerChip(side.business[control], side.outcomes[control]);
    return (
      <>
        {chip ? <Chip kind={chip.kind}>{t(chip.key)}</Chip> : '-'}
        {control === 'D' && side.engineAction ? (
          <span className={styles.judged}>
            {t('lab.r7.result.judged', { verdict: verdict(side.engineAction) })}
          </span>
        ) : null}
      </>
    );
  };
  const headline =
    versus && !reference
      ? versus.contexaChanged
        ? changedHeadline(t, versus.changedConditions, {
            from: verdict(versus.before.engineAction),
            to: verdict(versus.now.engineAction),
          })
        : t('lab.r7.result.headline.same', { verdict: verdict(versus.now.engineAction) })
      : t('lab.r7.result.headline.only', { verdict: verdict(nowSide.engineAction) });
  // Only a case sent as designed has its handling set in advance.
  const expectation = mine?.designed ? expectationOf(labCase?.classification) : 'none';
  const check = deltaKey(delta);

  return (
    <LabScreen
      step="result"
      type="T5"
      title={headline}
      purpose={t(
        reference && versus
          ? 'lab.r7.result.guideReference'
          : versus
            ? 'lab.r7.result.guide'
            : 'lab.r7.result.guideOnly',
      )}
      more={
        <>
          <DetailChip runId={runId} step={1} />
          <button type="button" className={styles.chip} onClick={() => assess.show()}>
            <Icon name="check" />
            {t('lab.r7.result.assess')}
          </button>
        </>
      }
      sourceLine={<SourceLine kind="run" runId={runId} />}
      back={{ to: '/lab/case', label: t('lab.r7.result.back') }}
      main={
        caseKey ? (
          <NextLink to={`/lab/change?case=${encodeURIComponent(caseKey)}`} label={t('lab.r7.result.next')} />
        ) : null
      }
    >
      <p className={styles.line}>
        <span className={styles.label}>{t('lab.r7.result.mine')}</span>
        <span className={styles.strong}>
          {mine?.call ? t(`lab.r7.send.call.${mine.call}`) : t('lab.r7.result.noCall')}
        </span>
        {mine?.callRight === true || mine?.callRight === false ? (
          <span className={styles.callMark} data-right={mine.callRight || undefined}>
            {t(mine.callRight ? 'lab.r7.result.callRight' : 'lab.r7.result.callOther')}
          </span>
        ) : null}
        {' · '}
        <span className={styles.label}>{t('lab.r7.case.expect.label')}</span>
        <span className={styles.strong}>
          {t(expectation === 'none' ? 'lab.r7.result.expectNone' : `lab.r7.case.expect.${expectation}`)}
        </span>
      </p>
      <table className={styles.table} data-compare>
        <thead>
          <tr>
            <th scope="col">{t('lab.r7.result.col.approach')}</th>
            {versus ? (
              <th scope="col">{t(reference ? 'lab.r7.result.col.reference' : 'lab.r7.result.col.before')}</th>
            ) : null}
            <th scope="col">{t('lab.r7.result.col.now')}</th>
          </tr>
        </thead>
        <tbody>
          {CONTROL_ORDER.map((control) => {
            const changed = versus?.changedControls.includes(control) ?? false;
            return (
              <tr key={control} data-contexa={control === 'D' || undefined}>
                <th scope="row">{t(`control.${control}.name`)}</th>
                {versus ? <td>{answer(versus.before, control)}</td> : null}
                <td data-now>
                  {answer(nowSide, control)}
                  {changed ? (
                    <span className={styles.changedTag}>{t('lab.r7.result.changedTag')}</span>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className={styles.line}>
        {t('lab.r7.result.exposed', { items: count(nowSide.exposedItems, language) })}
      </p>
      {check ? <p className={styles.line}>{t(check)}</p> : null}
      <Modal open={assess.open} onClose={assess.hide} title={t('lab.r7.result.assess')}>
        <AssessPanel runId={runId} reasons={options?.assessmentReasons ?? []} />
      </Modal>
    </LabScreen>
  );
}
