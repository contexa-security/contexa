import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useAnatomy } from '../../api/anatomy';
import { useBenchmark, type BenchmarkCase } from '../../api/benchmark';
import { useStepResult } from '../../api/lab';
import { useRunFacts, useRunQuality } from '../../api/promptQuality';
import { useRunScore } from '../../api/queries';
import { Fold } from '../../components/main/Fold';
import { Chip } from '../../components/main/Chip';
import { MainLink, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { utcTime } from '../../journey/format';
import { useEvidenceRun } from './evidence';
import { Hypotheses } from './Hypotheses';
import {
  blindNote,
  decidedSteps,
  firstStopping,
  INSIDER_NORMAL,
  KEEPS_IN,
  MAIN_CASES,
  resultChip,
  ROLE_PATHS,
  verdictChip,
} from './mainCases';
import { ReasonChain, VerdictHero } from './VerdictCard';
import styles from './ComparePages.module.css';
import evidenceStyles from './EvidencePages.module.css';

/** The existing security, whose answers to the insider's request the screen lists. */
const EXISTING = ['A', 'B', 'C1', 'C2'] as const;

/** The approaches the measured table compares: the two rules and Contexa. */
const COMPARED = ['C1', 'C2', 'D'] as const;

/** A control's results over a case's repeated runs, each with its count: "공격 통과(미탐) · 1회 중 1회". */
function measuredChips(
  t: ReturnType<typeof useTranslation>['t'],
  found: BenchmarkCase | undefined,
  control: string,
) {
  const results = found?.results[control] ?? {};
  const runs = found?.runs ?? 0;
  return Object.entries(results)
    .filter(([, n]) => n > 0)
    .map(([result, n]) => {
      const chip = resultChip(result);
      return {
        result,
        kind: chip.kind,
        label: t('main.5-3.count', { word: t(chip.key), n, runs, count: runs }),
      };
    });
}

/**
 * 5-3, what the AI weighed for the insider (IN-6 확정 설계, V-02): the insider's run (the visitor's own, else the
 * measurement's latest) opens on the decision that kept the documents in, and the visitor can pick any request Contexa
 * decided itself; a request refused by a decision already in force has none. For the picked request: the decision, the
 * explanations the model weighed with the facts for and against each, and the prompt lines its reason codes cite. Then
 * what the four existing approaches answered over the run, beside the measurement of the same request and of its normal
 * pair (the same person, time, device and way, with design documents). The sentence that the existing security let it
 * through and the AI held it on the facts it wove is said only when the run's own record makes it true (T1 all four let
 * it through, T3 the picked decision held it, T4 its reason cites two or more facts); a decision applied from the next
 * request on says what left before it, as the server counted it.
 */
export default function InsidePage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const evidence = useEvidenceRun(MAIN_CASES.insider);
  const { runId, results } = evidence;
  const score = useRunScore(runId, 'inside', 0);
  const decided = decidedSteps(score.data?.verdicts ?? []);
  const asked = Number(params.get('request'));
  const stepNo = decided.some((step) => step.stepNo === asked) ? asked : firstStopping(decided);
  const anatomy = useAnatomy(runId, stepNo);
  const facts = useRunFacts(runId, stepNo).data ?? null;
  const quality = useRunQuality(runId, stepNo).data ?? null;
  const contexa = useStepResult(runId, stepNo).data?.layers.find((layer) => layer.control === 'D') ?? null;
  const benchmark = useBenchmark(null);
  const attack = benchmark.data?.cases.find((candidate) => candidate.key === MAIN_CASES.insider);
  const normal = benchmark.data?.cases.find((candidate) => candidate.key === INSIDER_NORMAL);
  const protocols = benchmark.data?.scope.protocols ?? [];
  const measuredAt = protocols.length > 0 ? (protocols[protocols.length - 1]?.finishedAt ?? null) : null;
  const blind = benchmark.data?.suites.find((suite) => suite.suite === 'RULE_BLIND')?.cases ?? [];
  const note = blindNote(blind, [MAIN_CASES.insider]);

  if (evidence.pending || benchmark.isPending || (runId !== null && (score.isPending || anatomy.isPending))) {
    return (
      <MainScreen title={t('main.5-3.title')} main={null}>
        <StateScreen kind="loading" />
      </MainScreen>
    );
  }
  if (runId === null || !anatomy.data) {
    // Neither the visitor's own run nor a measured one yet: the way is to send it first, as on 2-3.
    return (
      <MainScreen
        title={t('main.5-3.title')}
        intro={t('main.5-3.intro.none')}
        main={<MainLink to={ROLE_PATHS.insider.request}>{t('main.console.toRequest')}</MainLink>}
        nextNote={null}
      >
        {null}
      </MainScreen>
    );
  }
  const recorded = anatomy.data.interpretation.recorded;
  const action = recorded.finalAction ?? recorded.proposedAction;
  const allPassed = EXISTING.every((control) => results?.[control] === 'MISSED');
  const held = action !== null && KEEPS_IN.has(action);
  // The distinct prompt lines the model's reason codes cite: the facts its reason weaves together.
  const woven = new Set((quality?.reasonCodes ?? []).map((code) => code.fact).filter((fact) => fact !== null))
    .size;
  const stopping = decided.find((step) => KEEPS_IN.has(step.action)) ?? null;
  const verdict = action ? t(`main.verdict.${action}`) : t('main.verdict.failed');
  const intro =
    allPassed && held && woven >= 2
      ? t('main.5-3.intro.proof', { step: stepNo, n: woven, verdict })
      : !held && stopping !== null && stopping.stepNo !== stepNo
        ? t('main.5-3.intro.other', { step: stepNo, verdict, held: stopping.stepNo })
        : t('main.5-3.intro.plain', { step: stepNo });
  // A held decision applied from the next request on: this request's document left before it, as the run recorded.
  const left = score.data?.business['D']?.exposedItems ?? null;
  const leftBefore =
    held && recorded.applied === 'NEXT_REQUEST' && contexa?.outcome === 'DELIVERED' && left !== null;
  return (
    <MainScreen title={t('main.5-3.title')} intro={intro}>
      {decided.length > 1 ? (
        <fieldset className={styles.picker}>
          <legend className={`${styles.pickerLegend} visually-hidden`}>{t('main.5-3.pick')}</legend>
          {decided.map((step) => {
            const chip = verdictChip({ finalAction: step.action, unresolved: false });
            return (
              <label
                key={step.stepNo}
                className={styles.pick}
                data-selected={step.stepNo === stepNo || undefined}
              >
                <input
                  type="radio"
                  name="request"
                  className="visually-hidden"
                  checked={step.stepNo === stepNo}
                  onChange={() => {
                    const next = new URLSearchParams(params);
                    next.set('request', String(step.stepNo));
                    setParams(next, { replace: true });
                  }}
                />
                <b className={styles.pickName}>{t('main.4-4.step', { n: step.stepNo })}</b>
                <Chip kind={chip.kind}>{t(chip.key)}</Chip>
              </label>
            );
          })}
        </fieldset>
      ) : null}
      <VerdictHero recorded={recorded} compact />
      {leftBefore ? (
        <Fold name="after-note" summary={t('main.5-3.after', { n: left, count: left })}>
          <p className={styles.note}>{t('main.5-3.afterWhy')}</p>
        </Fold>
      ) : null}
      {/* NW-8 (R-N2): what the AI weighed stays in view, the title's own question; the chain from the facts to the verdict, the
          four existing approaches' answers and the measured table fold under one line. */}
      <Hypotheses hypotheses={quality?.hypotheses ?? []} facts={facts} compact />
      <Fold name="inside" summary={t('main.5-3.fold')}>
        {/*
         * B-13: the existing security's results beside the chain from the facts to the verdict, then the measured table
         * over the whole width.
         */}
        <div className={evidenceStyles.verdict}>
          <div className={evidenceStyles.column}>
            <section className={styles.card} aria-labelledby="inside-rules">
              <h2 id="inside-rules" className={styles.cardTitle}>
                {t('main.5-3.rules')}
              </h2>
              {EXISTING.map((control) => {
                const chip = resultChip(results?.[control]);
                return (
                  <div key={control} className={styles.grid2}>
                    <b className={styles.rowName}>{t(`main.lane.${control}`)}</b>
                    <span className={styles.chips}>
                      <Chip kind={chip.kind}>{t(chip.key)}</Chip>
                    </span>
                  </div>
                );
              })}
            </section>
          </div>
          <ReasonChain codes={quality?.reasonCodes ?? []} facts={facts} action={action} />
        </div>
        <section className={styles.card} aria-labelledby="inside-table">
          <h2 id="inside-table" className={styles.cardTitle}>
            {t('main.5-3.table')}
          </h2>
          <div className={styles.grid3} data-head>
            <span />
            <span>{t('main.5-3.attack')}</span>
            <span>{t('main.5-3.normal')}</span>
          </div>
          {COMPARED.map((control) => (
            <div key={control} className={styles.grid3} data-contexa={control === 'D' || undefined}>
              <b className={styles.rowName}>{t(`main.lane.${control}`)}</b>
              <span className={styles.chips}>
                {measuredChips(t, attack, control).map((chip) => (
                  <Chip key={chip.result} kind={chip.kind}>
                    {chip.label}
                  </Chip>
                ))}
              </span>
              <span className={styles.chips}>
                {measuredChips(t, normal, control).map((chip) => (
                  <Chip key={chip.result} kind={chip.kind}>
                    {chip.label}
                  </Chip>
                ))}
              </span>
            </div>
          ))}
          <SourceBadge
            kind="repeated"
            label={t('main.5-3.measured', {
              runs: attack?.runs ?? 0,
              count: attack?.runs ?? 0,
              at: measuredAt ? utcTime(measuredAt).slice(0, 10) : '-',
            })}
          />
        </section>
        <p className={styles.note}>{note ? `${t('main.4-3.c2Note')} ${t(note)}` : t('main.4-3.c2Note')}</p>
      </Fold>
      <div className={styles.badges}>
        <SourceBadge
          kind={evidence.own ? 'run' : 'repeated'}
          label={t(evidence.own ? 'badge.run' : 'main.evidence.measured')}
          runId={runId}
          step={stepNo}
        />
      </div>
    </MainScreen>
  );
}
