import { useTranslation } from 'react-i18next';
import type { Subject } from '../../domain/subject';
import { Icon, type IconName } from '../Icon';
import styles from './SubjectChip.module.css';

/** Each kind's own icon, so a subject is never told by color alone (and no two kinds share one). */
const ICONS: Readonly<Record<Subject, IconName>> = {
  person: 'user',
  delegated: 'delegate',
  autonomous: 'agent',
  session: 'session',
};

/**
 * Who sends the screen's requests: a person, an agent acting for a person, an agent on its own, or an agent signed in
 * with its own account (docs/agent Agent중심-화면 AS-1). An outlined tag with an icon and the words; it is plain text,
 * not a button or a link, and its look differs from the result chips' filled pill (one look per role).
 */
export function SubjectChip({ subject }: { readonly subject: Subject }) {
  const { t } = useTranslation();
  const word = t(`subject.${subject}`);
  return (
    <span
      className={styles.chip}
      data-shape="tag"
      data-subject={subject}
      aria-label={t('subject.label', { subject: word })}
    >
      <Icon name={ICONS[subject]} className={styles.icon} />
      {word}
    </span>
  );
}
