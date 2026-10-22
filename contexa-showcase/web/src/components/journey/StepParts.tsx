import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Icon } from '../Icon';
import styles from './StepParts.module.css';

interface StepHeaderProps {
  readonly title: ReactNode;
  /** What the visitor does on this screen, in one line (R-5). */
  readonly purpose?: ReactNode;
  /** The screen's source tag, until the part's redo moves it to the source line under the body (R-10). */
  readonly source?: ReactNode;
}

/**
 * The title zone of the redesigned frame (화면재편-기획안 5절, R-5): the one headline saying what the screen is for and
 * one guide line saying what to do. The zone marks are what the automatic check (e2e/frame-audit.mjs) measures.
 */
export function StepHeader({ title, purpose = null, source = null }: StepHeaderProps) {
  return (
    // One block for the gap check: the headline and its guide line belong together (12-16 px apart by design).
    <header className={styles.header} data-zone="title" data-block>
      <h1 className={styles.title}>{title}</h1>
      {purpose || source ? (
        <p className={styles.purpose} data-guide>
          {purpose ? <span>{purpose}</span> : null}
          {source}
        </p>
      ) : null}
    </header>
  );
}

interface ActionBarProps {
  /** The screen before, as the quiet way back. */
  readonly back?: { readonly to: string; readonly label: string } | null;
  /** The one main action: a link naming the next screen's question, or the screen's own action (send). */
  readonly main?: ReactNode;
  /** Left over from the old frame (teaser band, other ways in, skip); not drawn, removed as each part is redone. */
  readonly start?: ReactNode;
  readonly teaser?: ReactNode;
  readonly skip?: boolean;
  /** "Skip this part", on a part's cover only (화면재편-기획안 8절). */
  readonly skipTo?: { readonly to: string; readonly label: string } | null;
}

/**
 * The action bar of the redesigned frame (화면재편-기획안 5절, R-2, R-6): "back" on the left and one main button on
 * the right, nothing else. On phones the whole bar is fixed at the bottom and the page keeps its height free, so it
 * never covers the content (F-8).
 */
export function ActionBar({ back = null, main = null, skipTo = null }: ActionBarProps) {
  const { t } = useTranslation();
  return (
    <nav className={styles.actions} aria-label={t('step.actions')} data-zone="actions">
      {back ? (
        <Link to={back.to} className={styles.back}>
          <Icon name="arrowLeft" className={styles.backIcon} />
          <span className={styles.backLabel}>{back.label}</span>
        </Link>
      ) : (
        <span />
      )}
      {main || skipTo ? (
        <div className={styles.main}>
          {skipTo ? (
            <Link to={skipTo.to} className={styles.skipPart}>
              {skipTo.label}
            </Link>
          ) : null}
          {main}
        </div>
      ) : null}
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
