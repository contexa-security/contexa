import type { CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useBenchmark, type BenchmarkCase, type ControlScore } from '../../api/benchmark';
import { useDetail } from '../../components/detail/useDetail';
import { MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { utcTime } from '../../journey/format';
import { sentPerCase } from '../benchmark/benchScope';
import styles from './ComparePages.module.css';

/** The rows of the matrix: the two rules and Contexa (설계서 5-4). */
const ROWS = ['C1', 'C2', 'D'] as const;

/** The order a row's dots are laid out in, so the same results stand together. */
const ATTACK_ORDER = ['STOPPED', 'PARTLY_STOPPED', 'MISSED'];
const NORMAL_ORDER = ['PASSED', 'PASSED_AFTER_CHECK', 'HALTED'];

/** A dot's colour by its result (the legend's four colours). */
const TONES: Readonly<Record<string, string>> = {
  STOPPED: 'stopped',
  PARTLY_STOPPED: 'partly',
  PASSED_AFTER_CHECK: 'partly',
  MISSED: 'bad',
  HALTED: 'bad',
  PASSED: 'passed',
};

interface Dot {
  readonly runId: string;
  readonly result: string;
}

/** Every run of the cases of one ground truth with the control's result, laid out by result. */
function dots(
  cases: readonly BenchmarkCase[],
  classification: string,
  control: string,
  order: readonly string[],
): Dot[] {
  const all = cases
    .filter((found) => found.classification === classification)
    .flatMap((found) =>
      Object.entries(found.runResults ?? {}).flatMap(([runId, results]) => {
        const result = results[control];
        return result ? [{ runId, result }] : [];
      }),
    );
  return [...all].sort((left, right) => rank(order, left.result) - rank(order, right.result));
}

function rank(order: readonly string[], result: string): number {
  const index = order.indexOf(result);
  return index < 0 ? order.length : index;
}

/**
 * 5-4, every repeated run (설계서 5-4): the measurement's runs as dots, one per run, for the two rules and Contexa,
 * attacks on the left and legitimate work on the right; a dot opens its own run. The row's counts are the server's
 * (missed attacks, legitimate work blocked); the headline says what they show only when they show it. The runs of the
 * disputed situations, which have no ground truth and so no dot, are named beside the count of runs.
 */
export default function RunsPage() {
  const { t } = useTranslation();
  const detail = useDetail();
  const benchmark = useBenchmark(null);
  if (benchmark.isPending || !benchmark.data) {
    return (
      <MainScreen title={t('main.7-3.titlePlain')} main={null}>
        <StateScreen kind={benchmark.isPending ? 'loading' : 'notReady'} />
      </MainScreen>
    );
  }
  const data = benchmark.data;
  const score = (control: string): ControlScore | undefined =>
    data.controls.find((candidate) => candidate.control === control);
  const contexa = score('D');
  const fixed = score('C1');
  const keepsBoth =
    contexa !== undefined &&
    contexa.missed === 0 &&
    contexa.falseBlock.hits === 0 &&
    fixed !== undefined &&
    (fixed.missed > 0 || fixed.falseBlock.hits > 0);
  const protocol = data.scope.protocols[data.scope.protocols.length - 1] ?? null;
  return (
    <MainScreen
      title={t(keepsBoth ? 'main.7-3.title' : 'main.7-3.titlePlain')}
      intro={
        <>
          {t('main.7-3.intro', { cases: data.scope.cases, repeat: sentPerCase(data), runs: data.scope.runs })}
          {/* V-11: the runs of the disputed situations count in the runs but have no dot; the server counts them. */}
          {data.scope.otherRuns > 0
            ? ` ${t('main.7-3.uncertain', {
                cases: data.caseCounts.UNCERTAIN,
                runs: data.scope.otherRuns,
                count: data.scope.otherRuns,
              })}`
            : null}
        </>
      }
    >
      <section className={styles.card} aria-labelledby="matrix-title">
        <h2 id="matrix-title" className="visually-hidden">
          {t('main.7-3.matrix')}
        </h2>
        <div className={styles.matrixRow} data-head>
          <span />
          <span>{t('main.7-3.attacks', { n: data.scope.attackRuns })}</span>
          <span>{t('main.7-3.normal', { n: data.scope.normalRuns })}</span>
          <span>{t('main.7-3.sum')}</span>
        </div>
        {ROWS.map((control, row) => {
          const found = score(control);
          const attack = dots(data.cases, 'THREAT', control, ATTACK_ORDER);
          const normal = dots(data.cases, 'NORMAL', control, NORMAL_ORDER);
          return (
            <div key={control} className={styles.matrixRow} data-contexa={control === 'D' || undefined}>
              <b className={styles.rowName}>{t(`main.lane.${control}`)}</b>
              {[attack, normal].map((list, side) => (
                <div
                  key={side}
                  className={styles.dots}
                  style={{ '--row-delay': `calc(var(--motion-row) * ${row})` } as CSSProperties}
                >
                  {list.map((dot) => (
                    <button
                      key={dot.runId}
                      type="button"
                      tabIndex={-1}
                      className={styles.dot}
                      data-dot
                      data-tone={TONES[dot.result] ?? 'none'}
                      aria-label={t('main.7-3.dot', {
                        run: dot.runId,
                        result: t(`main.result.${dot.result}`),
                      })}
                      title={`${dot.runId} · ${t(`main.result.${dot.result}`)}`}
                      onClick={() => detail.show(dot.runId, 1)}
                    />
                  ))}
                </div>
              ))}
              <p className={styles.sum}>
                {found
                  ? t('main.7-3.rowSum', { missed: found.missed, falseBlock: found.falseBlock.hits })
                  : '-'}
              </p>
            </div>
          );
        })}
      </section>
      <ul className={styles.legend}>
        {(['stopped', 'partly', 'bad', 'passed'] as const).map((tone) => (
          <li key={tone} className={styles.legendItem}>
            <span className={styles.dot} data-tone={tone} aria-hidden="true" />
            {t(`main.7-3.legend.${tone}`)}
          </li>
        ))}
      </ul>
      <p className={styles.note}>
        {contexa
          ? t('main.7-3.basis', { partly: contexa.partlyStopped, checked: contexa.friction.hits })
          : null}{' '}
        {t('main.7-3.c2')}
      </p>
      <div className={styles.badges}>
        {/* The measurement's internal id stays out of the words (V-48); it is kept as the badge's hover title. */}
        <span title={protocol?.protocolId ?? undefined}>
          <SourceBadge
            kind="repeated"
            label={t('main.7-3.measured', {
              at: protocol?.finishedAt ? utcTime(protocol.finishedAt).slice(0, 10) : '-',
            })}
          />
        </span>
        <Link to="/benchmark/cases" className={styles.link}>
          {t('main.7-3.cases')}
        </Link>
      </div>
    </MainScreen>
  );
}
