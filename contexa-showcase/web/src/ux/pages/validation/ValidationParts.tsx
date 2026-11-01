import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import type { BenchmarkRate } from '../../../api/benchmark';
import type { CaseResult } from '../../../api/types';
import { formatNumber } from '../../format';
import { evalOf } from '../../simulate/person';
import type { BarTone } from '../../ui';
import { EVAL_TONES } from '../../verdict';
import type { ResultSegment } from '../../validation/hooks';
import { rateCounts, ratePercent, rateRange } from '../../validation/shapes';
import styles from './Validation.module.css';

/**
 * A row's results as one bar of runs, each part with its count inside when it fits; the counts are also written in
 * words for assistive technology, so the bar is never read by colour alone.
 */
export function ResultBar({
  label,
  segments,
}: {
  readonly label: string;
  readonly segments: readonly ResultSegment[];
}) {
  const { i18n } = useTranslation();
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  const shown = segments.filter((segment) => segment.value > 0);
  return (
    <span className={styles.resultBar}>
      <span className={styles.resultTrack} aria-hidden="true">
        {shown.map((segment) => (
          <span
            key={segment.key}
            className={styles.resultPart}
            data-tone={segment.tone}
            style={{ inlineSize: `${(segment.value / Math.max(total, 1)) * 100}%` }}
            title={`${segment.label} ${segment.value}`}
          >
            {formatNumber(segment.value, i18n.language)}
          </span>
        ))}
      </span>
      <span className="ux-sr-only">
        {label}:{' '}
        {shown.map((segment) => `${segment.label} ${formatNumber(segment.value, i18n.language)}`).join(' · ')}
      </span>
    </span>
  );
}

/** The legend of the result bars: each kind once, with its tone. */
export function ResultLegend({
  items,
}: {
  readonly items: readonly { readonly label: string; readonly tone: BarTone }[];
}) {
  return (
    <ul className={styles.legend}>
      {items.map((item) => (
        <li key={item.label}>
          <i className={styles.swatch} data-tone={item.tone} aria-hidden="true" />
          {item.label}
        </li>
      ))}
    </ul>
  );
}

/** One dot per run with the run's result, each a link to the run's decision details. */
export function RunDots({
  label,
  runs,
}: {
  readonly label: string;
  readonly runs: readonly { readonly runId: string; readonly result: string }[];
}) {
  const { t } = useTranslation();
  return (
    <ul className={styles.dots} aria-label={label}>
      {runs.map((run) => {
        const graded = evalOf(run.result as CaseResult);
        return (
          <li key={run.runId}>
            <Link
              to={`/runs/${encodeURIComponent(run.runId)}`}
              className={styles.dot}
              data-tone={graded ? EVAL_TONES[graded] : 'none'}
              data-eval={graded ?? undefined}
              aria-label={t('ux.validation.dot', {
                run: run.runId,
                result: graded ? t(`ux.eval.${graded}`) : t('ux.validation.notScored'),
              })}
              title={run.runId}
            />
          </li>
        );
      })}
    </ul>
  );
}

/** The legend of the run dots: each result once, in the tone its dot takes (the old case map's legend). */
export function DotLegend() {
  const { t } = useTranslation();
  const items: readonly (readonly [string, string, string?])[] = [
    [t('ux.eval.correct'), EVAL_TONES.correct],
    [t('ux.eval.normal'), EVAL_TONES.normal],
    [t('ux.eval.afterCheck'), EVAL_TONES.afterCheck, 'afterCheck'],
    [t('ux.eval.partial'), EVAL_TONES.partial],
    [t('ux.eval.missed'), EVAL_TONES.missed],
    [t('ux.eval.falsePositive'), EVAL_TONES.falsePositive],
    [t('ux.validation.notScored'), 'none'],
  ];
  return (
    <ul className={styles.legend} aria-label={t('ux.validation.dotLegend')}>
      {items.map(([label, tone, graded]) => (
        <li key={label}>
          <i className={styles.dot} data-tone={tone} data-eval={graded} aria-hidden="true" />
          {label}
        </li>
      ))}
    </ul>
  );
}

/** A rate the server counted: the share, the counts, its 95% range and "few runs yet" where the server says so. */
export function RateText({
  rate,
  strong = false,
}: {
  readonly rate: BenchmarkRate;
  readonly strong?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const range = rateRange(rate, i18n.language);
  return (
    <span className={styles.rate}>
      <span className={strong ? styles.rateStrong : styles.rateValue}>
        {ratePercent(rate.rate, i18n.language)}
      </span>
      <span className={styles.sub}>
        <span className={styles.piece}>{rateCounts(rate, i18n.language)}</span>
        {range ? ' ' : null}
        {range ? <span className={styles.piece}>· {range}</span> : null}
      </span>
      {rate.preliminary ? <span className={styles.sub}>{t('ux.validation.preliminary')}</span> : null}
    </span>
  );
}

/** A thin meter of a rate with its 95% range: the bar to the share, the whisker over the range. */
export function RateMeter({ rate, contexa }: { readonly rate: BenchmarkRate; readonly contexa: boolean }) {
  if (rate.rate === null) {
    return null;
  }
  return (
    <span className={styles.meter} data-contexa={contexa || undefined} aria-hidden="true">
      <span className={styles.meterBar} style={{ inlineSize: `${rate.rate * 100}%` }} />
      {rate.low !== null && rate.high !== null ? (
        <span
          className={styles.meterRange}
          style={{ insetInlineStart: `${rate.low * 100}%`, inlineSize: `${(rate.high - rate.low) * 100}%` }}
        />
      ) : null}
    </span>
  );
}
