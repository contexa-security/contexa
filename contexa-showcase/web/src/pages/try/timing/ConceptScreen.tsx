import { useTranslation } from 'react-i18next';
import { useMeasuredCase } from '../../../api/measured';
import { routeFlow } from '../../../components/journey/flow';
import { RouteScreen } from '../../../components/journey/RouteScreen';
import { StateScreen } from '../../../components/StateScreen';
import { count, seconds } from '../../../journey/format';
import { useJourneyPosition } from '../../../journey/useJourneyPosition';
import { CASES } from '../experience';
import styles from './Timing.module.css';
import { middleRun } from './timingFormat';

/** A bar's share of the figure's time line; drawing only, the times themselves are the stored ones. */
function width(ms: number, longest: number): string {
  return `${Math.max(1, (ms / Math.max(1, longest)) * 100)}%`;
}

/** Where a time sits on the scale under the rows; drawing only, as the bars. */
function at(ms: number, longest: number): string {
  return `${Math.min(100, (ms / Math.max(1, longest)) * 100)}%`;
}

/** What one swatch of the legend shows: the bars' own looks (B-10). */
const LEGEND = [
  { id: 'held', swatch: 'held' },
  { id: 'out', swatch: 'out' },
  { id: 'judge', swatch: 'judge' },
] as const;

/**
 * Screen 4-0, the cover of part 4 (화면재편 T1): the part map, then the same export in time order in the two ways,
 * one row each. Stopping before the response holds the answer until the judgment is done; stopping from the next
 * request answers at once and judges behind it. Each row is the measured run the server marks as the middle of its
 * case (A3, A3A), with its judgment and answer times in the words of 4-1 (V-39) and what went out as its figure; a
 * time scale and a legend read the bars (B-10). The business-code notation is gone (it belongs to adoption, 5-3).
 */
export default function ConceptScreen() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const position = useJourneyPosition();
  const flow = routeFlow(t, position);
  const number = position.screen?.number ?? '4-0';
  const syncCase = useMeasuredCase(CASES.attacker.sync);
  const asyncCase = useMeasuredCase(CASES.attacker.async);
  const sync = middleRun(syncCase.data);
  const async = middleRun(asyncCase.data);
  const loading = syncCase.isPending || asyncCase.isPending;
  const shown =
    sync !== null && async !== null && sync.responseMs !== null && async.responseMs !== null && async.analysisMs !== null
      ? { sync, async, syncMs: sync.responseMs, asyncMs: async.responseMs, judgeMs: async.analysisMs }
      : null;
  const longest = shown ? Math.max(shown.syncMs, shown.asyncMs, shown.judgeMs) : 1;
  // The scale names the start, the answer held before the response and the judgment behind the next request (B-10);
  // a label already on the scale is not drawn twice.
  const ticks = shown
    ? [
        { ms: 0, label: t('p4.concept.tick', { seconds: '0' }) },
        { ms: shown.syncMs, label: t('p4.concept.tick', { seconds: seconds(shown.syncMs) }) },
        { ms: shown.judgeMs, label: t('p4.concept.tick', { seconds: seconds(shown.judgeMs) }) },
      ].filter((tick, index, all) => all.findIndex((other) => other.label === tick.label) === index)
    : [];

  return (
    <RouteScreen
      title={t(`screen.${number}.title`)}
      purpose={t(`screen.${number}.guide`)}
      sourceLine={shown ? <span>{t('p4.source.middle')}</span> : null}
      back={flow.back}
      main={flow.next}
    >
      {loading ? <StateScreen kind="loading" /> : null}
      {shown ? (
        <ol className={styles.rows} aria-label={t('p4.concept.figure')}>
          <li className={styles.row}>
            <span className={styles.rowName}>{t('p4.mode.sync')}</span>
            <span className={styles.track} aria-hidden="true">
              <span className={styles.fill} data-kind="held" style={{ width: width(shown.syncMs, longest) }} />
            </span>
            <span className={styles.rowLines}>
              <span>
                {t('p4.concept.sync', {
                  judge: shown.sync.analysisMs === null ? '-' : seconds(shown.sync.analysisMs),
                  seconds: seconds(shown.syncMs),
                })}
              </span>
              <span className={styles.rowItems} data-out={shown.sync.exposedItems > 0 || undefined}>
                {t('p4.items', { items: count(shown.sync.exposedItems, language) })}
              </span>
            </span>
          </li>
          <li className={styles.row}>
            <span className={styles.rowName}>{t('p4.mode.async')}</span>
            <span className={styles.track} aria-hidden="true">
              <span className={styles.judge} style={{ width: width(shown.judgeMs, longest) }} />
              <span className={styles.fill} data-kind="out" style={{ width: width(shown.asyncMs, longest) }} />
            </span>
            <span className={styles.rowLines}>
              <span>{t('p4.concept.async', { seconds: seconds(shown.asyncMs) })}</span>
              <span className={styles.rowItems} data-out={shown.async.exposedItems > 0 || undefined}>
                {t('p4.items', { items: count(shown.async.exposedItems, language) })}
              </span>
              <span>{t('p4.concept.judge', { seconds: seconds(shown.judgeMs) })}</span>
            </span>
          </li>
        </ol>
      ) : null}
      {shown ? (
        <>
          <div className={styles.axis} aria-hidden="true">
            <span className={styles.scale} data-axis>
              {ticks.map((tick) => (
                <span
                  key={tick.label}
                  className={styles.tick}
                  data-edge={tick.ms === 0 ? 'start' : tick.ms >= longest ? 'end' : undefined}
                  style={{ left: at(tick.ms, longest) }}
                >
                  {tick.label}
                </span>
              ))}
            </span>
          </div>
          <ul className={styles.legend} aria-label={t('p4.concept.legend')}>
            {LEGEND.map((entry) => (
              <li key={entry.id} className={styles.legendItem}>
                <span className={styles.swatch} data-swatch={entry.swatch} aria-hidden="true" />
                {t(`p4.concept.legend.${entry.id}`)}
              </li>
            ))}
          </ul>
        </>
      ) : loading ? null : (
        <p className={styles.note}>{t('p4.concept.none')}</p>
      )}
    </RouteScreen>
  );
}
