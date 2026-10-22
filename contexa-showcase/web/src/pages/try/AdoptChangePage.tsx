import type { ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useBenchmark } from '../../api/benchmark';
import { SourceLine } from '../../components/journey/FrameParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { count, dollars, seconds } from '../../journey/format';
import styles from './AdoptChangePage.module.css';

/** The four things that change when a system adopts Contexa (화면재편-구현계획 4절 5-3); the rest is on /adopt. */
const CELLS = ['code', 'flow', 'time', 'cost'] as const;
type Cell = (typeof CELLS)[number];

/**
 * Screen 5-3, what changes when you adopt it (화면재편-기획안 7절, T7): four cells, from the one line of code to the
 * cost. The code line and the request flow are what the library does; the judgment time and the cost per judgment are
 * the benchmark's measurement (the server's), and a value the measurement does not hold says so. The kept data, the
 * employee's and the security team's side and how to start live on the adopt screen.
 */
export default function AdoptChangePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const benchmark = useBenchmark(null);
  const engine = benchmark.data?.engine ?? null;
  const p50 = engine?.analysisP50Ms ?? null;
  const p95 = engine?.analysisP95Ms ?? null;
  const usd = engine?.costPerDecisionUsd ?? null;
  const tokens = engine?.tokensPerDecision ?? null;
  const values: Readonly<Record<Cell, ReactNode>> = {
    code: (
      <Trans
        i18nKey="p5.adopt.code"
        components={{ code: <code className={styles.inline} data-original /> }}
      />
    ),
    flow: t('p5.adopt.flow'),
    time:
      p50 !== null && p95 !== null
        ? t('p5.adopt.time', { p50: seconds(p50), p95: seconds(p95), mode: t('timing.mode.sync') })
        : t('p5.adopt.timeNone'),
    cost:
      usd === null
        ? t('adoptChange.value.costNone')
        : tokens === null
          ? t('p5.adopt.costOnly', { usd: dollars(usd) })
          : t('p5.adopt.cost', { usd: dollars(usd), tokens: count(Math.round(tokens), language) }),
  };
  return (
    <RouteScreen
      title={t('screen.5-3.title')}
      purpose={t('screen.5-3.guide')}
      sourceLine={engine ? <SourceLine kind="measured" /> : null}
    >
      <dl className={styles.cells} aria-label={t('screen.5-3.title')} data-block>
        {CELLS.map((cell) => (
          <div key={cell} className={styles.cell} data-cell={cell}>
            <dt className={styles.name}>{t(`adoptChange.name.${cell}`)}</dt>
            <dd className={styles.value}>{values[cell]}</dd>
          </div>
        ))}
      </dl>
    </RouteScreen>
  );
}
