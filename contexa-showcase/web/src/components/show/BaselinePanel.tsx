import { useTranslation } from 'react-i18next';
import type { UsualVsNow } from '../../api/anatomy';
import type { BaselineCardView } from '../../api/types';
import type { SceneRequest } from '../../domain/show';
import styles from './BaselinePanel.module.css';

interface BaselinePanelProps {
  readonly baseline: BaselineCardView;
  readonly request: SceneRequest;
  /**
   * What the engine was told about the request's usual-or-not, item by item, from the stored anatomy once the request
   * was decided; null before.
   */
  readonly received: readonly UsualVsNow[] | null;
  /**
   * How a difference from the usual is marked: as a danger in the attacker's scene, as a plain fact in the real
   * owner's, where the approval explains it (docs/showcase/화면설계서.md scene 3).
   */
  readonly differences?: 'alert' | 'plain';
}

const BAR_WIDTH = 8;
const BAR_GAP = 2;
const CHART_HEIGHT = 48;
const TICKS = [0, 6, 12, 18];

/**
 * What Contexa knows about the employee before the visitor acts as them, next to the request the case sends
 * (docs/showcase/데모-재설계.md 5A.3, H-03): the hours, networks and devices of the requests the engine learned, and
 * the request's own time, place, device and target as the case defines them. The screen compares nothing itself: the
 * visitor judges, and once the engine decided, the panel shows what the engine was told about each item (the stored
 * anatomy).
 */
export function BaselinePanel({ baseline, request, received, differences = 'alert' }: BaselinePanelProps) {
  const { t } = useTranslation();
  const hours = baseline.learned.hours;
  const peak = Math.max(1, ...hours);
  const width = hours.length * (BAR_WIDTH + BAR_GAP);
  return (
    <section className={styles.panel} aria-labelledby="baseline-title" data-marking={differences}>
      <h2 id="baseline-title" className={styles.title}>
        {t('show.baseline.title', { name: request.employeeName })}
      </h2>
      <figure className={styles.chart}>
        <figcaption className={styles.caption}>
          {t('show.baseline.hours', { n: baseline.learned.requests })}
        </figcaption>
        <svg
          className={styles.svg}
          viewBox={`0 0 ${width} ${CHART_HEIGHT}`}
          role="img"
          aria-label={hours.map((count, hour) => `${hour}:00 ${count}`).join(', ')}
        >
          {hours.map((count, hour) => {
            // Every bar is the learned count of its hour, the request's own hour included.
            const height = count === 0 ? 1 : Math.max(3, (count / peak) * CHART_HEIGHT);
            return (
              <rect
                key={hour}
                className={count === 0 ? styles.barEmpty : styles.bar}
                x={hour * (BAR_WIDTH + BAR_GAP)}
                y={CHART_HEIGHT - height}
                width={BAR_WIDTH}
                height={height}
              />
            );
          })}
          {/* The request's hour is a position on the axis, drawn as a line so it never reads as an amount. */}
          <line
            className={styles.nowLine}
            x1={request.hour * (BAR_WIDTH + BAR_GAP) + BAR_WIDTH / 2}
            x2={request.hour * (BAR_WIDTH + BAR_GAP) + BAR_WIDTH / 2}
            y1={0}
            y2={CHART_HEIGHT}
          />
        </svg>
        <div className={styles.ticks} aria-hidden="true">
          {TICKS.map((hour) => (
            <span
              key={hour}
              className={styles.tick}
              style={{ insetInlineStart: `${(hour / hours.length) * 100}%` }}
            >
              {hour}
            </span>
          ))}
        </div>
        <p className={styles.now}>
          {t('show.baseline.now', { time: request.time })} ·{' '}
          {t('show.baseline.nowCount', { count: hours[request.hour] ?? 0 })}
        </p>
      </figure>
      <h3 className={styles.compareTitle}>{t('show.baseline.learned')}</h3>
      <dl className={styles.learned}>
        <div className={styles.learnedRow}>
          <dt>{t('show.baseline.networks')}</dt>
          <dd>{baseline.learned.networks.join(', ') || '-'}</dd>
        </div>
        <div className={styles.learnedRow}>
          <dt>{t('show.baseline.devices')}</dt>
          <dd>{baseline.learned.devices.join(' · ') || '-'}</dd>
        </div>
      </dl>
      {received ? (
        <>
          <h3 className={styles.compareTitle}>{t('show.baseline.received')}</h3>
          <ul className={styles.signals}>
            {received.map((row) => {
              const state = row.inUsual === 'true' ? 'yes' : row.inUsual === 'false' ? 'no' : 'unknown';
              return (
                <li
                  key={row.dimension}
                  className={styles.signal}
                  data-differs={state === 'no'}
                  data-marking={differences}
                >
                  <span className={styles.mark}>{t(`anatomy.presence.${state}`)}</span>
                  <span className={styles.text}>
                    {t(`anatomy.dim.${row.dimension}`)} · {row.now ?? '-'}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className={styles.note}>{t('show.baseline.receivedSource')}</p>
        </>
      ) : (
        <p className={styles.note}>{t('show.baseline.judgeYourself')}</p>
      )}
      <p className={styles.source}>{t('lab.baseline.source', { template: baseline.templateId })}</p>
    </section>
  );
}
