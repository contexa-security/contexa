import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useVisitor } from '../../api/queries';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { AppHeader } from '../AppHeader';
import { TermScope } from '../common/Glossary';
import { Icon } from '../Icon';
import frame from './MainScreen.module.css';
import styles from './ChooseScreen.module.css';

interface ChooseScreenProps {
  /** The title: what this screen means, in one strong line (R-N4, 20 characters or so). */
  readonly title: ReactNode;
  /** What the visitor does here and gets, in one line (R-N4, 40 characters or less). */
  readonly intro?: ReactNode;
  /** The line the visitor's last run makes ("방금 확인한 것"); only the next-choosers have one. */
  readonly recap?: ReactNode;
  /** The small question over the cards (the start's "어느 쪽부터 볼까요?"). */
  readonly ask?: ReactNode;
  /** The cards. */
  readonly children: ReactNode;
  /** The one main button at the foot, where the screen has one beside the cards (the next-choosers' wrap-up). */
  readonly main?: ReactNode;
  /** The title and intro stand in the middle of the page: the start only. */
  readonly center?: boolean;
  /** The way back where it is not the lane's previous screen (the deeper hub leads back to the next-chooser). */
  readonly back?: { readonly to: string; readonly label: string } | null;
}

/**
 * The frame of a choosing screen (T9, docs/showcase/첫화면-선택형-체험-개선기획안.md 4절, 구현계획 NW-3): the top bar, a
 * strong title and one intro line, the cards, and a foot with the way back. It carries no place label and no table of
 * the next screen: the cards are the way on, and the top bar says the track and the step.
 */
export function ChooseScreen({
  title,
  intro = null,
  recap = null,
  ask = null,
  children,
  main,
  center = false,
  back,
}: ChooseScreenProps) {
  const { t } = useTranslation();
  useVisitor();
  const position = useJourneyPosition();
  const screen = position.screen;
  const previous = back === undefined ? position.previous : null;
  const way = back === undefined ? (previous ? { to: previous.path, label: t('frame.back') } : null) : back;
  return (
    <>
      <AppHeader />
      <main id="main" className={frame.page} data-type={screen?.type} data-screen={screen?.number}>
        <TermScope>
          <div className={styles.inner} data-center={center || undefined}>
            <header className={styles.head} data-zone="title" data-block>
              <h1 className={styles.title}>{title}</h1>
              {intro ? (
                <p className={styles.intro} data-guide>
                  {intro}
                </p>
              ) : null}
            </header>
            {recap ? (
              <p className={styles.recap} data-block>
                <b className={styles.recapLabel}>{t('next.recapLabel')}</b>
                <span>{recap}</span>
              </p>
            ) : null}
            <div className={styles.core} data-zone="body">
              {ask ? <p className={styles.ask}>{ask}</p> : null}
              {children}
            </div>
          </div>
          {way || main ? (
            <nav className={frame.foot} aria-label={t('step.actions')} data-zone="actions">
              {way ? (
                <Link to={way.to} className={frame.back}>
                  <Icon name="arrowLeft" className={frame.backIcon} />
                  <span>{way.label}</span>
                </Link>
              ) : (
                <span className={frame.back} />
              )}
              <span className={frame.next} />
              {main}
            </nav>
          ) : null}
        </TermScope>
      </main>
    </>
  );
}
