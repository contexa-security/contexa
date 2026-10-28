import { useTranslation } from 'react-i18next';
import { useAgentBenchmark } from '../../api/benchmark';
import { useBurstSnapshots } from '../../api/agentSnapshots';
import { SubjectChip } from '../../components/main/SubjectChip';
import { subjectOfSender } from '../../domain/subject';
import { count } from '../../journey/format';
import { BenchScreen, BenchSource } from './BenchScreen';
import { percent } from './benchPlace';
import styles from './Bench.module.css';

/**
 * The agent part of the benchmark (docs/agent Agent중심-화면 AS-11), beside the walk through the people's views: the
 * operator's recorded agent runs of the definitions in force, counted by the portal with the agent task's own scoring.
 * The one result line (what every existing control let through and how much of it Contexa stopped), the paths with their
 * counts, the normal work Contexa stopped, how the same case varied from run to run, the many-requests-at-once runs,
 * and what the numbers leave out: the cases nothing was measured for and the attacks Contexa also missed. Every figure
 * is the portal's; the screen counts nothing.
 */
export default function BenchAgentPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language;
  const benchmark = useAgentBenchmark();
  const view = benchmark.data ?? null;
  const bursts = useBurstSnapshots();
  const counted = view !== null && view.scope.runs > 0;
  const total = view?.total ?? null;
  return (
    <BenchScreen
      view="agent"
      type="table"
      title={t('bench.agent.title')}
      purpose={t('bench.agent.guide')}
      sourceLine={<BenchSource text={t('bench.agent.source')} />}
      main={null}
    >
      {benchmark.isPending ? <p className={styles.line}>…</p> : null}
      {view && !counted ? <p className={styles.line}>{t('bench.agent.empty')}</p> : null}
      {view && counted && total ? (
        <>
          <p className={styles.result}>
            {t('bench.agent.result', {
              missed: count(total.existingMissed, language),
              stopped: count(total.contexaStopped, language),
              percent: percent(total.contexaShare),
            })}
          </p>
          <p className={styles.line}>
            {t('bench.agent.scope', {
              runs: count(view.scope.runs, language),
              cases: count(view.scope.cases, language),
              from: view.scope.from?.slice(0, 10) ?? '-',
              to: view.scope.to?.slice(0, 10) ?? '-',
            })}
          </p>
          <table className={styles.table} aria-label={t('bench.agent.paths')}>
            <thead>
              <tr>
                <th scope="col">{t('bench.agent.col.path')}</th>
                <th scope="col">{t('bench.agent.col.runs')}</th>
                <th scope="col">{t('bench.agent.col.attacks')}</th>
                <th scope="col">{t('bench.agent.col.missed')}</th>
                <th scope="col">{t('bench.agent.col.stopped')}</th>
                <th scope="col">{t('bench.agent.col.normals')}</th>
                <th scope="col">{t('bench.agent.col.falseBlocks')}</th>
              </tr>
            </thead>
            <tbody>
              {view.byPath.map((row) => {
                const subject = subjectOfSender(row.path);
                return (
                  <tr key={row.path}>
                    <th scope="row">{subject ? <SubjectChip subject={subject} /> : row.path}</th>
                    <Figures row={row} language={language} />
                  </tr>
                );
              })}
              <tr>
                <th scope="row">{t('bench.agent.total')}</th>
                <Figures row={total} language={language} />
              </tr>
            </tbody>
          </table>
          <p className={styles.line}>
            {t('bench.agent.falseBlocks', {
              blocked: count(total.falseBlocks, language),
              normals: count(total.normals, language),
            })}
          </p>
          <p className={styles.line}>
            {t('bench.agent.variation', {
              differing: count(view.variation.differing, language),
              cells: count(view.variation.cells, language),
            })}
          </p>
          {bursts.bursts.length > 0 ? (
            <p className={styles.line}>
              {t('bench.agent.bursts')}:{' '}
              {bursts.bursts
                .map((pair) =>
                  t('bench.agent.burstLine', {
                    requests: count(pair.on.summary.requests, language),
                    off: count(pair.off.summary.modelCalls, language),
                    on: count(pair.on.summary.modelCalls, language),
                  }),
                )
                .join(' · ')}
            </p>
          ) : null}
          <p className={styles.line}>{t('bench.agent.missed', { n: count(view.contexaMissed.length, language) })}</p>
          {view.contexaMissed.length > 0 ? <p className={styles.line}>{view.contexaMissed.join(', ')}</p> : null}
          <p className={styles.line}>
            {t('bench.agent.notMeasured', { n: count(view.notMeasured.length, language) })}
          </p>
          {view.notMeasured.length > 0 ? <p className={styles.line}>{view.notMeasured.join(', ')}</p> : null}
        </>
      ) : null}
    </BenchScreen>
  );
}

function Figures({
  row,
  language,
}: {
  readonly row: {
    readonly runs: number;
    readonly attacks: number;
    readonly existingMissed: number;
    readonly contexaStopped: number;
    readonly normals: number;
    readonly falseBlocks: number;
  };
  readonly language: string;
}) {
  return (
    <>
      <td>{count(row.runs, language)}</td>
      <td>{count(row.attacks, language)}</td>
      <td>{count(row.existingMissed, language)}</td>
      <td>{count(row.contexaStopped, language)}</td>
      <td>{count(row.normals, language)}</td>
      <td>{count(row.falseBlocks, language)}</td>
    </>
  );
}
