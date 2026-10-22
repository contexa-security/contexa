import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useMeasuredCase } from '../../../api/measured';
import { Icon } from '../../../components/Icon';
import { routeFlow } from '../../../components/journey/flow';
import { SourceLine } from '../../../components/journey/FrameParts';
import { RouteScreen } from '../../../components/journey/RouteScreen';
import { useJourneyPosition } from '../../../journey/useJourneyPosition';
import { CASES } from '../experience';
import styles from './Timing.module.css';
import { itemsRange, secondsRange } from './timingFormat';

interface LeafProps {
  readonly mode: 'sync' | 'async';
  /** The kind of work the way fits. */
  readonly work: string;
  /** What the way costs, from the record; null when there is no record of it. */
  readonly cost: string | null;
}

/** Where a "yes" leads: the way, the work it fits and what it costs. */
function Leaf({ mode, work, cost }: LeafProps) {
  const { t } = useTranslation();
  return (
    <section className={styles.leaf} aria-labelledby={`when-${mode}`}>
      <h2 id={`when-${mode}`} className={styles.cardName}>
        {t(`p4.mode.${mode}`)}
      </h2>
      <p className={styles.line}>{work}</p>
      {cost ? <p className={styles.line}>{cost}</p> : null}
    </section>
  );
}

/**
 * One question of the flow and the way its "yes" leads to; the first question's "no" leads down to the second, the
 * second's "no" ends at a way of its own (V-53).
 */
function Question({
  text,
  leaf,
  no,
  noEnds = false,
}: {
  readonly text: string;
  readonly leaf: ReactNode;
  readonly no: string;
  readonly noEnds?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <li className={styles.question}>
      <p className={styles.questionText}>{text}</p>
      <div className={styles.branch}>
        <span className={styles.answer}>{t('p4.when.yes')}</span>
        <Icon name="arrowRight" className={styles.arrow} />
        {leaf}
      </div>
      <p className={styles.no}>
        <Icon name="arrowRight" className={noEnds ? styles.arrow : styles.down} />
        <span>{no}</span>
      </p>
    </li>
  );
}

/**
 * Screen 4-3, which way for which work (화면재편 T7): two questions that choose. Can it not be undone once it is out?
 * Yes: stop before the response. No: is it frequent and must it be fast? Yes: stop from the next request; no: the work
 * can wait, so stop before the response (V-53). Each way names
 * the work it fits and what it costs in the record: how long normal work waits for the answer when stopping before the
 * response (A3T), and what goes out of the same export when stopping from the next request (A3A). The "just seen" band
 * is gone (the part's wrap-up holds it).
 */
export default function WhenScreen() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const position = useJourneyPosition();
  const flow = routeFlow(t, position);
  const number = position.screen?.number ?? '4-3';
  const work = useMeasuredCase(CASES.owner.sync).data ?? null;
  const attack = useMeasuredCase(CASES.attacker.async).data ?? null;
  const syncCost = work?.responseMs ? t('p4.when.syncCost', { seconds: secondsRange(work.responseMs) }) : null;
  const asyncCost = attack?.exposedItems
    ? t('p4.when.asyncCost', { items: itemsRange(attack.exposedItems, language) })
    : null;

  return (
    <RouteScreen
      title={t(`screen.${number}.title`)}
      purpose={t(`screen.${number}.guide`)}
      sourceLine={syncCost || asyncCost ? <SourceLine kind="measured" /> : null}
      back={flow.back}
      main={flow.next}
    >
      <ol className={styles.questions} aria-label={t('p4.when.figure')}>
        <Question
          text={t('p4.when.q1')}
          leaf={<Leaf mode="sync" work={t('p4.when.syncWork')} cost={syncCost} />}
          no={t('p4.when.no')}
        />
        <Question
          text={t('p4.when.q2')}
          leaf={<Leaf mode="async" work={t('p4.when.asyncWork')} cost={asyncCost} />}
          no={t('p4.when.no2')}
          noEnds
        />
      </ol>
    </RouteScreen>
  );
}
