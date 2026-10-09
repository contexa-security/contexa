import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useJourneyPlace } from '../../journey/useJourneyPlace';
import { ActionChip } from '../common/ActionChip';
import { Icon } from '../Icon';
import styles from './StepParts.module.css';

interface StepHeaderProps {
  readonly title: ReactNode;
  /** What this screen is for, in one sentence; the step's name is already in the step bar (U-1). */
  readonly purpose?: ReactNode;
  /** The screen's one source tag (U-4), at the end of the purpose line. */
  readonly source?: ReactNode;
}

/**
 * The head of every screen (screen clarity rule U-1): the one headline and what the screen is for in one sentence, so
 * the visitor knows the screen's job before reading anything else.
 */
export function StepHeader({ title, purpose = null, source = null }: StepHeaderProps) {
  return (
    <header className={styles.header}>
      <h1 className={styles.title}>{title}</h1>
      {purpose || source ? (
        <p className={styles.purpose}>
          {/* One flow of words, so a term inside the sentence keeps its particle; the source tag sits after it. */}
          {purpose ? <span>{purpose}</span> : null}
          {source}
        </p>
      ) : null}
    </header>
  );
}

interface ActionBarProps {
  /** The step before, as a quiet way back. */
  readonly back?: { readonly to: string; readonly label: string } | null;
  /** In place of the way back on the first screen: the other ways in (concepts first, benchmark only). */
  readonly start?: ReactNode;
  /** The one main action: a link or button that names where it leads. */
  readonly main?: ReactNode;
  /** The teaser band (the next screen's question and measured number), drawn right over the main action. */
  readonly teaser?: ReactNode;
  /** Whether "skip" belongs here; a screen whose main action already goes where skip would go leaves it out. */
  readonly skip?: boolean;
}

/**
 * The same place at the end of every screen (U-3, redrawn 2026-10-08): one row with the way back on the left and, on
 * the right, "skip to act n" next to the one main action. A teaser band sits right over that row, so the question and
 * the button that answers it read as one. Actions about the screen's own content (details, originals) are not here;
 * they sit under that content (MoreRow).
 */
export function ActionBar({
  back = null,
  start = null,
  main = null,
  teaser = null,
  skip = true,
}: ActionBarProps) {
  const { t } = useTranslation();
  const place = useJourneyPlace();
  const skipTo = skip ? place.skip : null;
  return (
    <nav className={styles.actions} aria-label={t('step.actions')}>
      {teaser}
      <div className={styles.row}>
        {back ? (
          <span className={styles.back}>
            <ActionChip to={back.to} icon="arrowLeft">
              {back.label}
            </ActionChip>
          </span>
        ) : null}
        {start && !back ? <span className={`${styles.back} ${styles.start}`}>{start}</span> : null}
        {skipTo ? (
          <span className={styles.skip}>
            <ActionChip
              to={`${skipTo.path}${place.route === 'INTRO' ? '?route=intro' : ''}`}
              icon="skip"
              variant="quiet"
            >
              {place.route === 'INTRO' ? t('route.skipStep') : t(`act.skipTo.${skipTo.act ?? 2}`)}
            </ActionChip>
          </span>
        ) : null}
        {main ? <div className={styles.main}>{main}</div> : null}
      </div>
    </nav>
  );
}

/**
 * The row of "open" chips right under the content they open (details, the original, the full record): they belong to
 * that content, not to the way on, so they never sit in the action area.
 */
export function MoreRow({ children }: { readonly children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <div className={styles.moreRow} role="group" aria-label={t('step.more')}>
      {children}
    </div>
  );
}

/** The main button that names where it leads ("Next · Compare"), with an arrow. */
export function NextLink({ to, label }: { readonly to: string; readonly label: string }) {
  return (
    <Link to={to} className={styles.next} data-main>
      {label}
      <Icon name="arrowRight" className={styles.nextIcon} />
    </Link>
  );
}

interface RightMarkProps {
  readonly right: boolean | null | undefined;
  /** On phones only the check or cross shows; the word stays for screen readers (a narrow row keeps one line). */
  readonly compactOnPhone?: boolean;
}

/** Right or wrong as a green check or a red cross with its word, never by color alone. */
export function RightMark({ right, compactOnPhone = false }: RightMarkProps) {
  const { t } = useTranslation();
  if (right === null || right === undefined) {
    return <span className={styles.mark}>{t('mark.neither')}</span>;
  }
  return (
    <span className={styles.mark} data-right={right} data-compact={compactOnPhone || undefined}>
      <Icon name={right ? 'check' : 'cross'} className={styles.markIcon} />
      <span className={styles.markWord}>{t(right ? 'mark.right' : 'mark.wrong')}</span>
    </span>
  );
}
