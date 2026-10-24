import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useVisitor } from '../../api/queries';
import type { Screen } from '../../journey/journey';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { AppHeader } from '../AppHeader';
import { TermScope } from '../common/Glossary';
import { Icon } from '../Icon';
import styles from './MainScreen.module.css';

/** The main button when the screen's condition is not met yet: shown, not pressable, with what it waits for. */
export interface Waiting {
  readonly label: string;
  readonly hint: string;
}

export interface MainScreenProps {
  /** The one headline: a question or a conclusion in one sentence. */
  readonly title: ReactNode;
  /** What the visitor does here and learns, in one line. */
  readonly intro?: ReactNode;
  /** The feature's guide video preview under the intro line (가이드영상-계획.md 4절). */
  readonly guide?: ReactNode;
  /** The one core visual: the real data as a figure, a table or the console. */
  readonly children: ReactNode;
  /** The run going on right now, for the LIVE mark in the top bar. */
  readonly live?: string | null;
  /** The screen's own main action in place of the link to the next screen (Send, a choice that leads on). */
  readonly main?: ReactNode;
  /** The main link's words; the screen's main.{number}.cta by default. */
  readonly cta?: string;
  /**
   * The main button waits for something (a decision still being made): it shows, disabled, in one line, and the footer
   * says once what it waits for in place of the next screen's name (L-30).
   */
  readonly waiting?: Waiting | null;
  /** Quiet buttons beside the main one (the full record). */
  readonly extra?: ReactNode;
  /** What the footer says about the next screen, in place of its number and name. */
  readonly nextNote?: ReactNode;
  /**
   * The way on waits behind the screen's own action (7-2 before its send): the link to the next screen is drawn as a
   * quiet button, so one gold button asks to be pressed (L-38).
   */
  readonly quiet?: boolean;
  /** The headline is drawn inside the core (the opening's statement), so the frame keeps it for screen readers. */
  readonly titleInCore?: boolean;
  /** A group's cover (T0) draws no place label; its panel says where it is. */
  readonly cover?: boolean;
}

/**
 * The frame of every screen of the main flow (최종화면-구현계획 F0-3, 설계서 화면 틀): under the top bar the place label
 * "그룹 N · 이름 · 번호 화면 이름", one headline and one intro line, the core, and the footer with the way back, the
 * next screen's number and name, and one main button. The page carries the screen's type (T0-T8) for the automatic
 * check (e2e/frame-audit.mjs).
 */
export function MainScreen({
  title,
  intro = null,
  guide = null,
  children,
  live = null,
  main,
  cta,
  waiting = null,
  extra = null,
  nextNote,
  quiet = false,
  titleInCore = false,
  cover = false,
}: MainScreenProps) {
  const { t } = useTranslation();
  useVisitor();
  const position = useJourneyPosition();
  const screen = position.screen;
  const next = position.next;
  const previous = position.previous;
  return (
    <>
      <AppHeader live={live} />
      <main id="main" className={styles.page} data-type={screen?.type} data-screen={screen?.number}>
        <TermScope>
          <div className={styles.inner}>
            {screen && !cover ? <PlaceLabel screen={screen} /> : null}
            <header className={styles.head} data-zone="title" data-block>
              <h1 className={titleInCore ? 'visually-hidden' : styles.title}>{title}</h1>
              {intro ? (
                <p className={styles.intro} data-guide>
                  {intro}
                </p>
              ) : null}
              {guide}
            </header>
            <div className={styles.core} data-zone="body">
              {children}
            </div>
          </div>
          <nav className={styles.foot} aria-label={t('step.actions')} data-zone="actions">
            {previous ? (
              <Link to={previous.path} className={styles.back}>
                <Icon name="arrowLeft" className={styles.backIcon} />
                <span>{t('frame.back')}</span>
              </Link>
            ) : (
              <span className={styles.back} />
            )}
            <p className={styles.next}>
              {waiting ? (
                waiting.hint
              ) : nextNote !== undefined ? (
                nextNote
              ) : next ? (
                <>
                  <b className={styles.nextWord}>{t('frame.next')}</b>
                  <span className={styles.nextNumber}>{next.number}</span> {t(`main.${next.number}.name`)}
                </>
              ) : null}
            </p>
            {extra ? <div className={styles.extra}>{extra}</div> : null}
            {waiting ? (
              <span className={styles.cta} data-main aria-disabled="true" data-waiting>
                {waiting.label}
              </span>
            ) : main !== undefined ? (
              main
            ) : next && screen ? (
              <Link to={next.path} className={styles.cta} data-main data-quiet={quiet || undefined}>
                {cta ?? t(`main.${screen.number}.cta`)}
                <Icon name="arrowRight" className={styles.ctaIcon} />
              </Link>
            ) : null}
          </nav>
        </TermScope>
      </main>
    </>
  );
}

/** "그룹 2 · 공격 체험 · 2-1 요청 보내기": where the screen is, the same line on every screen of the flow. */
function PlaceLabel({ screen }: { readonly screen: Screen }) {
  const { t } = useTranslation();
  return (
    <p className={styles.loc}>
      {t('frame.loc.group', { group: screen.act, name: t(`group.${screen.act}`) })}
      <span className={styles.locScreen}>
        {' · '}
        {screen.number} {t(`main.${screen.number}.name`)}
      </span>
    </p>
  );
}

/** A quiet button beside the main one in the footer (the full record, the reasons' source). */
export function GhostButton({
  children,
  onClick,
}: {
  readonly children: ReactNode;
  readonly onClick: () => void;
}) {
  return (
    <button type="button" className={styles.ghost} onClick={onClick}>
      {children}
    </button>
  );
}

/** A main button that is the screen's own action (send) and not a link. */
export function MainButton({
  children,
  onClick,
  disabled = false,
}: {
  readonly children: ReactNode;
  readonly onClick: () => void;
  readonly disabled?: boolean;
}) {
  return (
    <button type="button" className={styles.cta} data-main onClick={onClick} disabled={disabled}>
      {children}
      <Icon name="arrowRight" className={styles.ctaIcon} />
    </button>
  );
}

/** A main link to a screen other than the next one (the end's choices). */
export function MainLink({ to, children }: { readonly to: string; readonly children: ReactNode }) {
  return (
    <Link to={to} className={styles.cta} data-main>
      {children}
      <Icon name="arrowRight" className={styles.ctaIcon} />
    </Link>
  );
}
