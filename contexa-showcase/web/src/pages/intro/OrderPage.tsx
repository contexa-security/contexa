import { useTranslation } from 'react-i18next';
import { useLabOptions } from '../../api/lab';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { Icon, type IconName } from '../../components/Icon';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { count } from '../../journey/format';
import styles from './OrderPage.module.css';

/** The three tries of the route, by the cases each sends first (7.1 to 7.3). */
const TRIES = [
  { key: 'try1', caseKey: 'A3', answer: 'stop' },
  { key: 'try2', caseKey: 'A3T', answer: 'pass' },
  { key: 'try3', caseKey: 'A6T', answer: 'learning' },
] as const;

/** How every try runs (g5-order): labels, not buttons. */
const WAYS: readonly { readonly key: string; readonly icon: IconName }[] = [
  { key: 'call', icon: 'user' },
  { key: 'live', icon: 'play' },
  { key: 'mode', icon: 'clock' },
];

/**
 * G5, the order (g5-order, 7.5): the three tries, each with who, what and the right answer (try 3 with what to watch),
 * the definition of someone using a stolen account, and how every try runs. The names, times, projects and counts are
 * the case definitions'.
 */
export default function OrderPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const options = useLabOptions().data ?? null;
  const what = (caseKey: string, key: string) => {
    const labCase = options?.cases.find((candidate) => candidate.key === caseKey);
    if (!labCase || !options) {
      return '-';
    }
    const employee = options.employees.find((candidate) => candidate.key === labCase.conditions.employee);
    const slot = options.timeSlots.find((candidate) => candidate.slot === labCase.conditions.timeSlot);
    const request = labCase.requests[0];
    return t(`order.${key}.what`, {
      name: employee?.displayName ?? '-',
      when: slot ? t(`lab.slot.${slot.slot}`, { time: slot.representativeTime }) : '-',
      project: request?.project ?? '-',
      items: request?.items === null || request?.items === undefined ? '-' : count(request.items, language),
      steps: labCase.requests.length,
    });
  };
  return (
    <RouteScreen
      title={t('order.title')}
      purpose={t('order.purpose')}
      source={options ? <SourceMark kind="CASE">
            {t('order.source', { keys: TRIES.map((entry) => entry.caseKey).join(' · ') })}
          </SourceMark> : null}
      nextLabel={t('order.next')}
      more={
        <ActionChip to="/intro/approaches?route=intro" icon="arrowLeft" variant="open">
          {t('order.approaches')}
        </ActionChip>
      }
    >
      <ol className={styles.tries}>
        {TRIES.map((entry) => (
          <li key={entry.key} className={styles.try}>
            <span className={styles.who}>{t(`order.${entry.key}.who`)}</span>
            <span className={styles.what}>{what(entry.caseKey, entry.key)}</span>
            <span className={styles.answer} data-answer={entry.answer}>
              <span className={styles.answerName}>
                {entry.answer === 'learning' ? t('order.watch') : t('order.answerName')}
              </span>
              {t(`order.answer.${entry.answer}`)}
            </span>
          </li>
        ))}
      </ol>
      <p className={styles.definition}>
        <span className={styles.definitionName}>{t('order.stolenName')}</span>
        {t('order.stolen')}
      </p>
      <ul className={styles.ways}>
        {WAYS.map((way) => (
          <li key={way.key} className={styles.way}>
            <Icon name={way.icon} />
            {t(`order.way.${way.key}`)}
          </li>
        ))}
      </ul>
    </RouteScreen>
  );
}
