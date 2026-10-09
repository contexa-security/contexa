import { useTranslation } from 'react-i18next';
import { useLabOptions } from '../../api/lab';
import { useBaseline } from '../../api/queries';
import { SourceMark } from '../../components/common/SourceMark';
import { HourBars } from '../../components/journey/HourBars';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { CASES } from '../try/experience';
import styles from './LearningPages.module.css';

/**
 * Prior learning 1 (g-learn-why, 7.3): without knowing the usual, an export at 3 a.m. cannot be called unusual; with
 * it, it can. The second panel is the engine's real learned hours of the employee whose account try 1 used, with that
 * request's hour marked; whether the hour was ever learned is the record's count, not the screen's judgement.
 */
export default function LearnWhyPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const options = useLabOptions();
  const attack = options.data?.cases.find((candidate) => candidate.key === CASES.attacker.sync) ?? null;
  const slot =
    options.data?.timeSlots.find((candidate) => candidate.slot === attack?.conditions.timeSlot) ?? null;
  const baseline = useBaseline(attack?.conditions.employee ?? null);
  const hour = slot ? Number(slot.representativeTime.slice(0, 2)) : null;
  const when = slot ? t(`lab.slot.${slot.slot}`, { time: slot.representativeTime }) : '';
  const learned = baseline.data?.learned ?? null;
  const atHour = learned && hour !== null ? (learned.hours[hour] ?? 0) : null;

  return (
    <RouteScreen
      title={t('learnWhy.title', { when })}
      purpose={t('learnWhy.purpose')}
      source={
        baseline.data ? (
          <SourceMark kind="ENGINE" recordedAt={baseline.data.capturedAt ?? null}>
            {t('learnWhy.source', { template: baseline.data.templateId })}
          </SourceMark>
        ) : null
      }
    >
      {baseline.isPending || options.isPending ? <StateScreen kind="loading" /> : null}
      <div className={styles.twoPanels}>
        <section className={styles.panel} data-tone="unknown" aria-labelledby="learn-unknown">
          <h2 id="learn-unknown" className={styles.panelLabel}>
            {t('learnWhy.unknown.title')}
          </h2>
          <span className={styles.bigMark} aria-hidden="true">
            ?
          </span>
          <p className={styles.panelText}>{t('learnWhy.unknown.text')}</p>
        </section>
        <section className={styles.panel} data-tone="known" aria-labelledby="learn-known">
          <h2 id="learn-known" className={styles.panelLabel}>
            {t('learnWhy.known.title')}
          </h2>
          {learned && hour !== null ? (
            <>
              <HourBars hours={learned.hours} mark={hour} markLabel={when} />
              <p className={styles.panelText}>
                {atHour === 0
                  ? t('learnWhy.known.zero', { n: count(learned.requests, language), hour })
                  : t('learnWhy.known.some', {
                      n: count(learned.requests, language),
                      hour,
                      count: count(atHour ?? 0, language),
                    })}
              </p>
            </>
          ) : null}
        </section>
      </div>
      <p className={styles.conclusion}>{t('learnWhy.so')}</p>
      <ul className={styles.tags}>
        <li className={styles.tag}>
          <span className={styles.tagName}>{t('learnWhy.demo.name')}</span>
          {t('learnWhy.demo.text')}
        </li>
        <li className={styles.tag}>
          <span className={styles.tagName}>{t('learnWhy.real.name')}</span>
          {t('learnWhy.real.text')}
        </li>
      </ul>
    </RouteScreen>
  );
}
