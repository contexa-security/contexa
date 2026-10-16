import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { QualityRibbonView } from '../../api/promptQuality';
import { Icon } from '../Icon';
import { ribbonHolds, RIBBON_ITEMS, type RibbonItem } from './factWords';
import styles from './Facts.module.css';

interface QualityRibbonProps {
  readonly ribbon: QualityRibbonView;
  /** The prompt line of the first fact behind each item, from the facts and the inspection the screen read. */
  readonly lines?: Readonly<Record<RibbonItem, number | null>> | undefined;
  /** Leads a failing item to the fact behind it; without it a failing item is stated, not pressed. */
  readonly onShow?: ((item: RibbonItem, line: number | null) => void) | undefined;
}

/** The words of an item: the server's counts, or that the inspection has not run yet. */
function itemText(t: ReturnType<typeof useTranslation>['t'], ribbon: QualityRibbonView, item: RibbonItem): string {
  switch (item) {
    case 'source':
      return t('quality.ribbon.source', { n: ribbon.withSource, total: ribbon.facts });
    case 'accuracy':
      return ribbon.factAccuracy === null
        ? t('quality.ribbon.accuracyPending')
        : t('quality.ribbon.accuracy', { n: ribbon.factAccuracy.matched, total: ribbon.factAccuracy.total });
    default:
      return ribbon.contradictions === null
        ? t('quality.ribbon.contradictionsPending')
        : t('quality.ribbon.contradictions', { n: ribbon.contradictions });
  }
}

/**
 * The AI input check in one line (U-1, quality ribbon): the facts with a source, the facts that match their source,
 * the contradictions, and what is not known, each the server's count of this run's official inspection. An item that
 * does not hold shows a cross with its counts as large as a passing one, and leads to its fact when pressed; an item
 * the inspection gives says it is not inspected yet while the seal has no inspection.
 */
export function QualityRibbon({ ribbon, lines, onShow }: QualityRibbonProps) {
  const { t } = useTranslation();
  const holds = ribbonHolds(ribbon);
  return (
    <div className={styles.ribbon} role="group" aria-label={t('quality.ribbon.title')}>
      <span className={styles.ribbonTitle}>{t('quality.ribbon.title')}</span>
      <ul className={styles.ribbonItems}>
        {RIBBON_ITEMS.map((item) => {
          const ok = holds[item];
          if (ok === null) {
            return (
              <li key={item} className={styles.ribbonItem} data-ok="pending" data-item={item}>
                <Icon name="clock" className={styles.ribbonMark} />
                <span>{itemText(t, ribbon, item)}</span>
              </li>
            );
          }
          const content: ReactNode = (
            <>
              <Icon name={ok ? 'check' : 'cross'} className={styles.ribbonMark} />
              <span>{itemText(t, ribbon, item)}</span>
              <span className="visually-hidden">{` ${t(ok ? 'quality.ribbon.ok' : 'quality.ribbon.failed')}`}</span>
            </>
          );
          return (
            <li key={item} className={styles.ribbonItem} data-ok={ok} data-item={item}>
              {!ok && onShow ? (
                <button
                  type="button"
                  className={styles.ribbonButton}
                  onClick={() => onShow(item, lines?.[item] ?? null)}
                >
                  {content}
                </button>
              ) : (
                content
              )}
            </li>
          );
        })}
        <li className={styles.ribbonItem} data-item="unknown">
          <span aria-hidden="true">·</span>
          <span>{t('quality.ribbon.unknown', { n: ribbon.unknown })}</span>
        </li>
      </ul>
    </div>
  );
}
