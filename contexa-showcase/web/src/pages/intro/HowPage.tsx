import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Icon, type IconName } from '../../components/Icon';
import { RouteScreen } from '../../components/journey/RouteScreen';
import styles from './HowPage.module.css';

/** The nine cells in the order a request passes them; the names are the inside panel's (panel slide). */
const CELLS: readonly { readonly id: string; readonly icon: IconName }[] = [
  { id: 'request', icon: 'box' },
  { id: 'usual', icon: 'user' },
  { id: 'company', icon: 'book' },
  { id: 'history', icon: 'clock' },
  { id: 'prompt', icon: 'code' },
  { id: 'judgement', icon: 'search' },
  { id: 'decision', icon: 'check' },
  { id: 'followUp', icon: 'mail' },
  { id: 'learning', icon: 'refresh' },
];

/**
 * G-how, how it judges (g-how, 7.3): the nine cells every request passes, in one flow whose last cell feeds the usual
 * behaviour back, with what each cell does under the flow for the cell pressed, and the two ways of judging side by
 * side. The cells carry the same names as the inside panel of the tries, so the visitor meets the same nine words.
 */
export default function HowPage() {
  const { t } = useTranslation();
  const [picked, setPicked] = useState(0);
  const cell = CELLS[picked] ?? CELLS[0];
  return (
    <RouteScreen title={t('how.title')} purpose={t('how.purpose')}>
      <section className={styles.figure} aria-labelledby="how-flow">
        <h2 id="how-flow" className={styles.label}>
          {t('how.flowLabel')}
        </h2>
        <ol className={styles.flow}>
          {CELLS.map((item, index) => (
            <li key={item.id} className={styles.item}>
              <button
                type="button"
                className={styles.cell}
                aria-pressed={picked === index}
                onClick={() => setPicked(index)}
              >
                <span className={styles.number}>{index + 1}</span>
                <Icon name={item.icon} className={styles.icon} />
                <span className={styles.name}>{t(`inside.cell.${item.id}`)}</span>
              </button>
            </li>
          ))}
        </ol>
        <p className={styles.loop}>
          <Icon name="refresh" className={styles.loopIcon} />
          {t('how.loop')}
        </p>
        {cell ? (
          <p className={styles.picked} aria-live="polite">
            <span className={styles.pickedName}>
              {picked + 1} · {t(`inside.cell.${cell.id}`)}
            </span>
            {t(`how.cell.${cell.id}`)}
          </p>
        ) : null}
      </section>
      <div className={styles.compare}>
        <section className={styles.way} data-way="old" aria-labelledby="how-old">
          <h2 id="how-old" className={styles.wayName}>
            {t('how.old.name')}
          </h2>
          <p className={styles.wayText}>{t('how.old.text')}</p>
        </section>
        <section className={styles.way} data-way="new" aria-labelledby="how-new">
          <h2 id="how-new" className={styles.wayName}>
            {t('how.new.name')}
          </h2>
          <p className={styles.wayText}>{t('how.new.text')}</p>
        </section>
      </div>
    </RouteScreen>
  );
}
