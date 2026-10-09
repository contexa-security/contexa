import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { StreamProgress } from '../api/types';
import { exposureSeconds, itemsAt, streamState } from '../domain/stream';
import styles from './StreamMeter.module.css';

interface StreamMeterProps {
  readonly stream: StreamProgress;
  /** Replays the recorded pace from the first item; reduced motion or off shows the final state at once. */
  readonly play?: boolean;
}

const COUNT = new Intl.NumberFormat('en-US');
const SECONDS = new Intl.NumberFormat('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
const TICK_MS = 100;

function prefersReducedMotion(): boolean {
  return (
    typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

/**
 * Deck p.11: the moment flowing data stops. The bar and the count follow the stored samples; the exposure sentence
 * says how much left before the cut and for how long, never hiding it.
 */
export function StreamMeter({ stream, play = false }: StreamMeterProps) {
  const { t } = useTranslation();
  const animate = play && !prefersReducedMotion() && stream.firstLineMs !== null;
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!animate) {
      return;
    }
    const started = Date.now();
    const timer = window.setInterval(() => {
      const now = Date.now() - started;
      setElapsed(now);
      if ((stream.firstLineMs ?? 0) + now >= stream.endMs) {
        window.clearInterval(timer);
      }
    }, TICK_MS);
    return () => window.clearInterval(timer);
  }, [animate, stream]);

  const finished = !animate || (stream.firstLineMs ?? 0) + elapsed >= stream.endMs;
  const items = finished ? stream.delivered : itemsAt(stream.samples, (stream.firstLineMs ?? 0) + elapsed);
  const state = finished ? streamState(stream) : 'flowing';
  const span = stream.total ?? stream.delivered;
  const share = span > 0 ? Math.min(1, items / span) : 0;
  const count =
    stream.total === null
      ? t('stream.countNoTotal', { items: COUNT.format(items) })
      : t('stream.count', { items: COUNT.format(items), total: COUNT.format(stream.total) });

  return (
    <section className={styles.meter} data-state={state} aria-labelledby="stream-title">
      <div className={styles.head}>
        <h3 id="stream-title" className={styles.title}>
          {t('stream.title')}
        </h3>
        <span className={styles.state}>{t(`stream.state.${state}`)}</span>
      </div>
      <div
        className={styles.bar}
        role="progressbar"
        aria-label={t('stream.progress')}
        aria-valuemin={0}
        aria-valuemax={span}
        aria-valuenow={items}
      >
        <span className={styles.fill} style={{ inlineSize: `${share * 100}%` }} />
      </div>
      <p className={styles.count} data-testid="stream-count">
        {count}
      </p>
      {finished ? (
        <p className={styles.exposure}>
          {t(`stream.exposure.${streamState(stream)}`, {
            items: COUNT.format(stream.delivered),
            seconds: SECONDS.format(exposureSeconds(stream)),
          })}
        </p>
      ) : null}
    </section>
  );
}
