import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePublicSettings } from '../../api/settings';
import { Modal } from '../../components/common/Modal';
import { Icon } from '../../components/Icon';
import { ApproachSettings } from '../../components/inside/ApproachSettings';
import frame from '../../components/journey/FrameParts.module.css';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { CONTROL_ORDER, type ControlId } from '../../domain/verdict';
import styles from './ApproachesPage.module.css';

/** The methods inside the application, in the order a request passes them before the task itself. */
const INSIDE: readonly ControlId[] = ['B', 'C1', 'C2', 'D'];

/**
 * Screen 5-0, the cover of part 5 (화면재편-기획안 7절, T1): the part map, then the five security methods one line each
 * by the names every later screen uses, with the industry term once in parentheses (11.1), what each sees and what it
 * misses; then where they sit, in one line (the old G3-2 figure): the web firewall outside the application, the rest
 * inside it before the task, titled as a real deployment's places, with the demo's own set-up said plainly under it.
 * The settings each method runs with in this demo are behind the one chip, named as the published criteria since no
 * request is judged here (V-54), in one window (their values are the running stack's, /api/settings).
 */
export default function ApproachesPage() {
  const { t } = useTranslation();
  const settings = usePublicSettings();
  const [open, setOpen] = useState(false);
  const [shown, setShown] = useState<ControlId>('D');

  return (
    <RouteScreen
      title={t('screen.5-0.title')}
      purpose={t('screen.5-0.guide')}
      more={
        <button type="button" className={frame.detail} onClick={() => setOpen(true)}>
          <Icon name="search" className={frame.detailIcon} />
          {t('p5.five.open')}
        </button>
      }
    >
      {/* On phones the five lines are cards swiped one at a time; the list takes the keyboard's focus to scroll. */}
      <ol className={styles.rows} aria-label={t('p5.five.list')} tabIndex={0}>
        {CONTROL_ORDER.map((control) => (
          <li key={control} className={styles.row} data-contexa={control === 'D' || undefined}>
            <p className={styles.name}>
              <span className={styles.nameWord}>{t(`control.${control}.name`)}</span>{' '}
              <span className={styles.term}>{t(`p5.five.term.${control}`)}</span>
            </p>
            <p className={styles.line}>
              <Icon name="check" className={styles.seesIcon} />
              <span>
                <span className={styles.label}>{t('p5.five.sees')}</span> {t(`p5.five.${control}.sees`)}
              </span>
            </p>
            <p className={styles.line}>
              <Icon name="cross" className={styles.missesIcon} />
              <span>
                <span className={styles.label}>{t('p5.five.misses')}</span> {t(`p5.five.${control}.misses`)}
              </span>
            </p>
          </li>
        ))}
      </ol>
      <figure className={styles.where}>
        {/* The line is where each method sits in a real deployment; the demo's own set-up is the caption (V-54). */}
        <p className={styles.whereTitle}>{t('p5.five.where.title')}</p>
        <ol className={styles.path} aria-label={t('p5.five.where.figure')}>
          <li className={styles.stop}>{t('p5.five.where.request')}</li>
          <li className={styles.stop}>
            <Icon name="arrowRight" className={styles.arrow} />
            <span className={styles.zone}>{t('p5.five.where.outside')}</span>
            <span className={styles.step}>{t('control.A.name')}</span>
          </li>
          <li className={styles.insideStop}>
            <Icon name="arrowRight" className={styles.arrow} />
            <span className={styles.inside}>
              <span className={styles.zone}>{t('p5.five.where.inside')}</span>
              {INSIDE.map((control, index) => (
                <span key={control} className={styles.stop}>
                  {index > 0 ? <Icon name="arrowRight" className={styles.arrow} /> : null}
                  <span className={styles.step} data-contexa={control === 'D' || undefined}>
                    {t(`control.${control}.name`)}
                  </span>
                </span>
              ))}
              <span className={styles.stop}>
                <Icon name="arrowRight" className={styles.arrow} />
                <span className={styles.step}>{t('p5.five.where.task')}</span>
              </span>
            </span>
          </li>
        </ol>
        <figcaption className={styles.honest}>{t('p5.five.where.honest')}</figcaption>
      </figure>
      <Modal open={open} onClose={() => setOpen(false)} title={t('p5.five.settings')}>
        <div className={styles.pick} role="group" aria-label={t('p5.five.settings.pick')}>
          {CONTROL_ORDER.map((control) => (
            <button
              key={control}
              type="button"
              className={styles.pickButton}
              aria-pressed={shown === control}
              onClick={() => setShown(control)}
            >
              {t(`control.${control}.name`)}
            </button>
          ))}
        </div>
        {settings.data ? <ApproachSettings control={shown} settings={settings.data} /> : null}
        {settings.isError ? <p>{t('settings.unavailable')}</p> : null}
      </Modal>
    </RouteScreen>
  );
}
