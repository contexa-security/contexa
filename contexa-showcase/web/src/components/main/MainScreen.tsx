import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useVisitor } from '../../api/queries';
import { subjectOfScreen, type Subject } from '../../domain/subject';
import type { Screen } from '../../journey/journey';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { AppHeader } from '../AppHeader';
import { GuidePreview } from '../guide/GuidePreview';
import { guideForScreen } from '../guide/guideConfig';
import { TermScope } from '../common/Glossary';
import { Icon } from '../Icon';
import styles from './MainScreen.module.css';
import { SubjectChip } from './SubjectChip';

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
  /**
   * A guide video link of the screen's own, over the one its number finds in the guide list (가이드영상-제작기획안.md
   * 4.1절): beside the title on a wide screen, under the intro on a narrow one.
   */
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
  /** Who sends this screen's requests; the chip sits on the place label's line (docs/agent Agent중심-화면 AS-1). */
  readonly subject?: Subject | undefined;
  /** The way back where the screen has no lane to go back in (the wrap-up): an address, or none to show no way back. */
  readonly back?: string | null;
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
  subject,
  back,
}: MainScreenProps) {
  const { t } = useTranslation();
  useVisitor();
  const position = useJourneyPosition();
  const screen = position.screen;
  const next = position.next;
  const previous = back === undefined ? (position.previous?.path ?? null) : back;
  const guideId = guideForScreen(screen?.number);
  return (
    <>
      <AppHeader live={live} />
      <main id="main" className={styles.page} data-type={screen?.type} data-screen={screen?.number}>
        <TermScope>
          <div className={styles.inner}>
            {screen && !cover ? <PlaceLabel screen={screen} subject={subject ?? subjectOfScreen(screen.number)} /> : null}
            <header className={styles.head} data-zone="title" data-block>
              <h1 className={titleInCore ? 'visually-hidden' : styles.title}>{title}</h1>
              {intro ? (
                <p className={styles.intro} data-guide>
                  {intro}
                </p>
              ) : null}
              {guide ?? (guideId ? <GuidePreview id={guideId} /> : null)}
            </header>
            <div className={styles.core} data-zone="body">
              {children}
            </div>
          </div>
          <nav className={styles.foot} aria-label={t('step.actions')} data-zone="actions">
            {previous ? (
              <Link to={previous} className={styles.back}>
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
                  {t(`main.${next.number}.name`)}
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

/**
 * "사람 · 계정을 훔친 사람 · 요청 보내기": where the screen is, the same line on every screen of the flow: the track and
 * the case it walks (a deeper screen says "더 깊이" in place of a track), then the screen's own name.
 */
function PlaceLabel({ screen, subject }: { readonly screen: Screen; readonly subject: Subject | undefined }) {
  const { t } = useTranslation();
  const lane = screen.lane ?? '';
  const own = screen.track === 'A' || screen.track === 'H' ? t(`top.track.${screen.track}`) : null;
  const prefix = own ?? (lane === 'end' || lane === 'start' ? null : t('place.deeper'));
  const label = (
    <p className={styles.loc}>
      {prefix ? `${prefix} · ` : ''}
      {t(`lane.${lane}`)}
      <span className={styles.locScreen}>
        {' · '}
        {t(`main.${screen.number}.name`)}
      </span>
    </p>
  );
  if (!subject) {
    return label;
  }
  return (
    <div className={styles.place} data-place>
      {label}
      <SubjectChip subject={subject} />
    </div>
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
