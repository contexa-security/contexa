import { useTranslation } from 'react-i18next';
import type { BenchmarkEngine } from '../../api/benchmark';
import { count, dollars, seconds } from '../../journey/format';
import styles from './OpsStrip.module.css';

/** The verdicts in the order the bar stacks them, each with its colour. */
const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const;

/**
 * EV-6, the engine as an operated product (최종화면-구현계획 5차): over every measured decision, how its verdicts split,
 * how long a decision took (median and 95th percentile), what one cost and how many it could not make. Every value is
 * the benchmark's own measurement; the bars only scale the measured counts and times.
 */
export function OpsStrip({ engine }: { readonly engine: BenchmarkEngine }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const slowest = Math.max(engine.analysisP95Ms ?? 0, engine.analysisP50Ms ?? 0, 1);
  return (
    <section className={styles.ops} aria-labelledby="ops-title">
      <h2 id="ops-title" className={styles.title}>
        {t('main.ops.title', { n: count(engine.decisions, language) })}
      </h2>
      <div className={styles.tiles}>
        <div className={styles.tile} data-wide>
          <span className={styles.label}>{t('main.ops.split')}</span>
          <span className={styles.stack} aria-hidden="true">
            {ACTIONS.map((action) =>
              (engine.actions[action] ?? 0) > 0 ? (
                <span
                  key={action}
                  className={styles.segment}
                  data-action={action}
                  style={{ flexGrow: engine.actions[action] ?? 0 }}
                />
              ) : null,
            )}
          </span>
          <ul className={styles.legend}>
            {ACTIONS.filter((action) => (engine.actions[action] ?? 0) > 0).map((action) => (
              <li key={action} className={styles.legendItem} data-action={action}>
                <span className={styles.dot} aria-hidden="true" />
                {t(`main.verdict.${action}`)} <b>{count(engine.actions[action] ?? 0, language)}</b>
              </li>
            ))}
          </ul>
        </div>
        <div className={styles.tile}>
          <span className={styles.label}>{t('main.ops.time')}</span>
          {[
            { key: 'p50', ms: engine.analysisP50Ms },
            { key: 'p95', ms: engine.analysisP95Ms },
          ].map((row) => (
            <span key={row.key} className={styles.timeRow}>
              <span className={styles.timeName}>{t(`main.ops.${row.key}`)}</span>
              <span className={styles.timeTrack}>
                <span
                  className={styles.timeFill}
                  data-key={row.key}
                  style={{ inlineSize: `${((row.ms ?? 0) / slowest) * 100}%` }}
                />
              </span>
              <b className={styles.timeValue}>
                {row.ms === null ? '—' : `${seconds(row.ms)}${t('main.unit.seconds')}`}
              </b>
            </span>
          ))}
        </div>
        <div className={styles.tile}>
          <span className={styles.label}>{t('main.ops.cost')}</span>
          <b className={styles.big}>
            {engine.costPerDecisionUsd === null ? '—' : `$${dollars(engine.costPerDecisionUsd)}`}
          </b>
          <span className={styles.note}>{t('main.ops.costNote')}</span>
        </div>
        <div className={styles.tile}>
          <span className={styles.label}>{t('main.ops.failed')}</span>
          <b className={styles.big} data-clean={engine.unresolved === 0 || undefined}>
            {count(engine.unresolved, language)}
            <span className={styles.of}> / {count(engine.decisions, language)}</span>
          </b>
          <span className={styles.note}>{t('main.ops.failedNote')}</span>
        </div>
      </div>
    </section>
  );
}
