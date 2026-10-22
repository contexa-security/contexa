import { useTranslation } from 'react-i18next';
import { useUrlModal } from '../../components/common/useUrlModal';
import { VERDICTS, type VerdictPresentation } from '../../domain/verdict';
import { count } from '../../journey/format';
import { BenchScreen, BenchSource } from './BenchScreen';
import { useBenchView, useReasonMatch } from './benchData';
import { BENCH_MODALS } from './benchPlace';
import { mostLikelyActions } from './benchShapes';
import { StackBar, type StackTone } from './charts/StackBar';
import styles from './Bench.module.css';

/** The explanations in the bar's order, each with a tone that carries no judgement. */
const EXPLANATIONS: readonly (readonly [string, StackTone])[] = [
  ['H1', 'neutral'],
  ['H2', 'accent'],
  ['H3', 'accentHatch'],
  ['H4', 'quiet'],
  ['H5', 'quiet'],
  ['SEVERAL', 'quiet'],
  ['NONE', 'quiet'],
];

/**
 * The run truths drawn as rows, in this order; the open situations' decisions are a row too, so the rows hold every
 * decision the model answered (R-09 of docs/showcase/영상전-검토.md).
 */
const TRUTHS = ['THREAT', 'NORMAL', 'UNCERTAIN'] as const;

/** The actions in the order the visitors meet them, the others after. */
const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];

function rank(action: string): number {
  const at = ACTIONS.indexOf(action);
  return at === -1 ? ACTIONS.length : at;
}

/**
 * B-5 of docs/showcase/벤치마크-구현계획.md (a table view): whether the AI's judgment can be trusted, from the portal's
 * counts of the model calls: the runs and the decisions apart (V-26), how to read the bar, per run truth the explanation
 * each decision's last answer judged most likely, in words (P-22), with the attack decisions that judged legitimate work
 * most likely by the action each still took (V-46); whether each decision is the model's last answer, unchanged (G4)
 * and whether the lines its reasons cite state those facts (G5); and how often the response check asked again, why,
 * and how the answers moved (findings 11 and 12 of the v21 plan, shown as they are).
 */
export default function BenchReasoningPage() {
  const { t, i18n } = useTranslation();
  const method = useUrlModal(BENCH_MODALS.method);
  const { view, empty, state } = useBenchView();
  const reasonMatch = useReasonMatch(view?.spec?.settingHash ?? null);
  const engine = view?.engine ?? null;
  const reasoning = engine?.reasoning ?? null;
  const agreement = engine?.agreement ?? null;
  const reasons = reasonMatch;
  const n = (value: number) => count(value, i18n.language);
  // An engine action in the visitors' word for it, the action itself where it is none of the four.
  const actionWord = (action: string) => {
    const found = (VERDICTS as Readonly<Record<string, VerdictPresentation | undefined>>)[action];
    return found ? t(found.labelKey) : action;
  };
  const threatLegitimate = reasoning?.mostLikely['THREAT']?.['H1'] ?? 0;
  const threatActions = reasoning ? (mostLikelyActions(reasoning)?.['THREAT']?.['H1'] ?? null) : null;
  return (
    <BenchScreen
      view="reasoning"
      type="table"
      title={t('bench.chart.reasoning.title')}
      purpose={t('bench.chart.reasoning.guide')}
      sourceLine={
        engine ? <BenchSource text={t('frame.source.measured')} onOpen={() => method.show()} /> : null
      }
    >
      {state}
      {empty ? <p className={styles.line}>{t('bench.r7.empty')}</p> : null}
      {engine && !reasoning ? <p className={styles.line}>{t('bench.chart.reasoning.none')}</p> : null}
      {view && engine && reasoning ? (
        <>
          <p className={styles.line}>
            {t('bench.chart.reasoning.scope', { runs: n(view.scope.runs), decisions: n(engine.decisions) })}
          </p>
          <p className={styles.line}>{t('bench.chart.reasoning.read')}</p>
          <StackBar
            rows={TRUTHS.filter((truth) => reasoning.mostLikely[truth] !== undefined).map((truth) => ({
              key: truth,
              label: t(`bench.chart.reasoning.truth.${truth}`),
              segments: EXPLANATIONS.map(([id, tone]) => ({
                key: id,
                label: t(`bench.chart.reasoning.explanation.${id}`),
                count: reasoning.mostLikely[truth]?.[id] ?? 0,
                tone,
              })),
            }))}
            summary={t('bench.chart.reasoning.summary')}
            rowHead={t('bench.chart.reasoning.truthHead')}
            countLabel={(value) => t('bench.chart.reasoning.decisions', { n: n(value) })}
            inside="label"
          />
          {threatLegitimate > 0 && threatActions ? (
            <p className={styles.line}>
              {t('bench.chart.reasoning.h1Threat', {
                n: n(threatLegitimate),
                actions: Object.entries(threatActions)
                  .filter(([, decisions]) => decisions > 0)
                  .sort(([a], [b]) => rank(a) - rank(b))
                  .map(([action, decisions]) =>
                    t('bench.chart.reasoning.action', { verdict: actionWord(action), n: n(decisions) }),
                  )
                  .join(' · '),
              })}
            </p>
          ) : null}
          <ul className={styles.proofLines}>
            {agreement && agreement.modelAnswered > 0 ? (
              <li>
                {t('bench.r7.proof.agreement', {
                  as: agreement.asAnswered,
                  answered: agreement.modelAnswered,
                  technical: agreement.technical,
                  held: agreement.held,
                })}
              </li>
            ) : null}
            {reasons && reasons.total > 0 ? (
              <li>{t('bench.r7.proof.reasons', { hits: reasons.hits, total: reasons.total })}</li>
            ) : null}
            <li>{t('bench.chart.reasoning.retried', { n: n(reasoning.retried) })}</li>
            {Object.entries(reasoning.flips).map(([flip, decisions]) => {
              const [from = flip, to = ''] = flip.split('->');
              return (
                <li key={flip} data-flip={flip}>
                  {t('bench.chart.reasoning.flip', {
                    from: actionWord(from),
                    to: actionWord(to),
                    n: n(decisions),
                  })}
                </li>
              );
            })}
          </ul>
          {reasoning.topRetryReasons.length > 0 ? (
            <div
              className={styles.tableScroll}
              role="region"
              aria-label={t('bench.chart.reasoning.reasons')}
              tabIndex={0}
            >
              <table className={styles.table}>
                <caption className={styles.caption}>{t('bench.chart.reasoning.reasons')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('bench.chart.reasoning.reason')}</th>
                    <th scope="col">{t('bench.chart.time.decisions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {reasoning.topRetryReasons.map((reason) => (
                    <tr key={reason.reason}>
                      <th scope="row">
                        <code data-original>{reason.reason}</code>
                      </th>
                      <td>{n(reason.decisions)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </>
      ) : null}
    </BenchScreen>
  );
}
