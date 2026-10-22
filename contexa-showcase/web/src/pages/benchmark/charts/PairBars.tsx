import { useTranslation } from 'react-i18next';
import type { BlindSpot, BlindSpotCase } from '../../../api/benchmark';
import { sharedNormals } from '../benchShapes';
import { RunCells } from './RunCells';
import styles from './Charts.module.css';

type Translate = ReturnType<typeof useTranslation>['t'];

/** Contexa's results in a case's counted runs as the portal counted them: "차단 4 · 공격 통과(미탐) 1". */
function contexaWords(t: Translate, contexa: Readonly<Record<string, number>>): string {
  return Object.entries(contexa)
    .filter(([, n]) => n > 0)
    .map(([result, n]) =>
      t('bench.r7.proof.result', { word: t(`main.result.${result}`, { defaultValue: result }), n }),
    )
    .join(' · ');
}

interface PairBarsProps {
  readonly proof: BlindSpot;
  /** A case's name as the benchmark writes it. */
  readonly nameOf: (key: string) => string;
}

/**
 * B-1 of docs/showcase/벤치마크-구현계획.md: each blind-spot attack over the normal work of the same conditions, a cell
 * per run every existing approach let through (or let pass) with what Contexa did in it, misses included. The pairs,
 * the runs and every count are the portal's; the attacks without a pair follow alone.
 */
export function PairBars({ proof, nameOf }: PairBarsProps) {
  const { t } = useTranslation();
  const attacks = new Map(proof.attacks.map((row) => [row.key, row]));
  const normals = new Map(proof.normals.map((row) => [row.key, row]));
  const pairs = proof.pairs ?? [];
  const paired = new Set(pairs.map((pair) => pair.attack));
  const alone = proof.attacks.filter((row) => !paired.has(row.key));
  // V-64: normal work several pairs name, which the criteria count once (the portal names it).
  const shared = new Set(sharedNormals(proof));
  const line = (row: BlindSpotCase, side: 'attack' | 'normal') => (
    <div className={styles.pairLine} data-side={side} data-case={row.key}>
      <p className={styles.pairName}>
        <span className={styles.pairSide}>{t(`bench.chart.pair.${side}`)}</span>
        {nameOf(row.key)}
      </p>
      <RunCells runs={row.passedRuns ?? []} label={t('bench.chart.pair.cells', { name: nameOf(row.key) })} />
      <p className={styles.pairValue}>
        {t('bench.r7.proof.allPassedValue', { passed: row.allPassed, runs: row.runs })}
        {row.allPassed > 0 ? ` · ${t('bench.chart.pair.contexa')} ${contexaWords(t, row.contexa)}` : ''}
      </p>
      {side === 'normal' && shared.has(row.key) ? (
        <p className={styles.pairValue} data-shared>
          {t('bench.chart.pair.shared')}
        </p>
      ) : null}
    </div>
  );
  const groups = [...new Set(pairs.map((pair) => pair.group))];
  return (
    <div className={styles.pairs} data-chart="pairs" data-count="exempt">
      {groups.map((group) => (
        <section
          key={group}
          className={styles.pairGroup}
          aria-label={t(`bench.chart.pair.group.${group}`, { defaultValue: group })}
        >
          <h3 className={styles.pairGroupTitle}>
            {t(`bench.chart.pair.group.${group}`, { defaultValue: group })}
          </h3>
          {pairs
            .filter((pair) => pair.group === group)
            .map((pair) => {
              const attack = attacks.get(pair.attack);
              const normal = pair.normal ? normals.get(pair.normal) : undefined;
              return attack ? (
                <div key={`${pair.attack}-${pair.normal ?? ''}`} className={styles.pair}>
                  {line(attack, 'attack')}
                  {normal ? line(normal, 'normal') : null}
                </div>
              ) : null;
            })}
        </section>
      ))}
      {alone.length > 0 ? (
        <section className={styles.pairGroup} aria-label={t('bench.chart.pair.group.alone')}>
          <h3 className={styles.pairGroupTitle}>{t('bench.chart.pair.group.alone')}</h3>
          {alone.map((row) => (
            <div key={row.key} className={styles.pair}>
              {line(row, 'attack')}
            </div>
          ))}
        </section>
      ) : null}
    </div>
  );
}
