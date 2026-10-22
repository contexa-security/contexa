import { useTranslation } from 'react-i18next';
import { useLabOptions } from '../../api/lab';
import { useBaseline } from '../../api/queries';
import { routeFlow } from '../../components/journey/flow';
import { SourceLine } from '../../components/journey/FrameParts';
import { HourBars } from '../../components/journey/HourBars';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { CASES } from '../try/experience';
import styles from './LearningPages.module.css';

/**
 * Screen 3-0, the cover of part 3 (화면재편 T1): the part map, the part's question as the title, and two panels side
 * by side. Without the usual there is nothing to compare the 3 a.m. export with; with it, the engine's learned hours of
 * the employee whose account try 1 used show, with that request's hour marked, and one line says how many learned
 * requests came at that hour, read from the record (the screen counts nothing). The teaser card, the closing line and
 * the demo / real-service tags are gone (R-1, R-6); the main button names the next screen's question.
 */
export default function LearnWhyPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const flow = routeFlow(t, useJourneyPosition());
  const options = useLabOptions();
  const attack = options.data?.cases.find((candidate) => candidate.key === CASES.attacker.sync) ?? null;
  const slot =
    options.data?.timeSlots.find((candidate) => candidate.slot === attack?.conditions.timeSlot) ?? null;
  const baseline = useBaseline(attack?.conditions.employee ?? null);
  // The request's hour as the case's time slot gives it ("03:17" is hour 3), only to place the mark and read its bar.
  const hour = slot ? Number(slot.representativeTime.slice(0, 2)) : null;
  const learned = baseline.data?.learned ?? null;
  const atHour = learned && hour !== null ? (learned.hours[hour] ?? 0) : null;
  const loading = options.isPending || baseline.isLoading;
  const n = learned ? count(learned.requests, language) : '';

  return (
    <RouteScreen
      // The question names the case's own hour (IN-6: never words bound to one case).
      title={t('screen.3-0.title', { clock: slot?.representativeTime ?? '…' })}
      purpose={t('screen.3-0.guide')}
      sourceLine={learned ? <SourceLine kind="learned" /> : null}
      back={flow.back}
      main={flow.next}
    >
      {loading ? <StateScreen kind="loading" /> : null}
      <div className={styles.panels}>
        <section className={styles.panel} data-tone="unknown" aria-labelledby="why-unknown">
          <h2 id="why-unknown" className={styles.label}>
            {t('p3.why.unknown.title')}
          </h2>
          <p className={styles.unknownMark} aria-hidden="true">
            ?
          </p>
          <p className={styles.text}>{t('p3.why.unknown.text')}</p>
        </section>
        <section className={styles.panel} data-tone="known" aria-labelledby="why-known">
          <h2 id="why-known" className={styles.label}>
            {t('p3.why.known.title')}
          </h2>
          {learned ? (
            <>
              <HourBars hours={learned.hours} mark={hour} markLabel={t('p3.why.mark')} />
              {atHour !== null ? (
                <p className={styles.text}>
                  {atHour === 0
                    ? t('p3.why.known.zero', { n })
                    : t('p3.why.known.some', { n, at: count(atHour, language) })}
                </p>
              ) : null}
            </>
          ) : loading ? null : (
            <p className={styles.text}>{t('p3.learned.none')}</p>
          )}
        </section>
      </div>
    </RouteScreen>
  );
}
