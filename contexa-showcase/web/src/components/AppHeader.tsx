import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useLocation } from 'react-router-dom';
import { useGuides, videoOf } from '../api/guides';
import { useJourney } from '../api/journey';
import { useStats, useVisitor } from '../api/queries';
import { setLanguage } from '../i18n';
import { count } from '../journey/format';
import { DEFAULT_ROUTE, MORE_PATH, STEPS, topicOf } from '../journey/journey';
import { useJourneyPlace } from '../journey/useJourneyPlace';
import { useGlossary } from './common/glossaryTerms';
import { Modal } from './common/Modal';
import { GUIDE_IDS, guideEntry } from './guide/guideConfig';
import { Icon } from './Icon';
import styles from './AppHeader.module.css';

/** Where the menu leads, the same from every screen: the flow's start, "learn more" and the spaces outside the flow. */
const MENU = [
  { to: '/', key: 'frame.menu.restart' },
  { to: MORE_PATH, key: 'frame.menu.more' },
  { to: '/videos', key: 'frame.menu.guides' },
  { to: '/lab', key: 'frame.menu.lab' },
  { to: '/benchmark', key: 'frame.menu.benchmark' },
  { to: '/adopt', key: 'frame.menu.adopt' },
  { to: '/privacy', key: 'frame.menu.privacy' },
] as const;

/**
 * Where a screen outside the main flow is: the space's name (the lab, the benchmark, ...), the step or view inside
 * it, and for a space walked in order (the lab) how far along its steps the screen is.
 */
export interface Space {
  readonly name: string;
  readonly step?: string | null;
  /** 0-100 for a space walked in order; none for a space of views. */
  readonly progress?: number | null;
}

interface AppHeaderProps {
  readonly space?: Space | null;
  /** The run going on right now: the LIVE mark shows while it runs (설계서 2-2). */
  readonly live?: string | null;
}

/**
 * The top bar (최종화면-구현계획 F0-2): the brand, the LIVE mark while a real request runs, today's real runs and the
 * decisions so far as the server counts them, the terms and the menu. Under it, on a track of the main flow, the
 * track's name and its six steps with the finished ones ticked and the current one in gold (구현계획 NW-6); on a
 * "learn more" screen the way back to the flow; elsewhere the space and its step.
 */
export function AppHeader({ space = null, live = null }: AppHeaderProps = {}) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const openGlossary = useGlossary();
  // The list of the guide videos is in the menu once a video of the new flow was recorded (the old ones are not listed).
  const guides = useGuides();
  const hasGuides = GUIDE_IDS.some(
    (id) => guideEntry(id).kind !== 'legacy' && videoOf(guides.data, id, language) !== undefined,
  );
  const place = useJourneyPlace();
  const stats = useStats();
  const [open, setOpen] = useState(false);
  const track = place.screen?.track === 'A' || place.screen?.track === 'H' ? place.screen.track : null;
  const step = place.screen?.step ?? null;
  const other = language === 'ko' ? 'en' : 'ko';
  const more = place.screen?.act === 0 || place.more;
  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <header className={styles.header} data-zone="top">
        <div className={styles.bar}>
          <Link className={styles.brand} to="/">
            CONTEXA <span className={styles.brandDemo}>{t('top.demo')}</span>
          </Link>
          {live ? (
            <span className={styles.live} role="status" data-live>
              <span className={styles.liveDot} aria-hidden="true" />
              <span className={styles.liveText}>{t('top.live')}</span>
              <span className={styles.liveRun}>{live}</span>
            </span>
          ) : null}
          <span className={styles.spacer} />
          {stats.data ? (
            <span className={styles.stats}>
              {t('top.stats.today')}{' '}
              <b>{t('top.stats.todayCount', { n: count(stats.data.runs.today, language) })}</b>
              {stats.data.engineDecisions === undefined ? null : (
                <>
                  {' · '}
                  {t('top.stats.decisions')}{' '}
                  <b>{t('top.stats.decisionsCount', { n: count(stats.data.engineDecisions, language) })}</b>
                </>
              )}
            </span>
          ) : null}
          <button type="button" className={styles.terms} onClick={() => openGlossary()}>
            {t('top.terms')}
          </button>
          <button
            type="button"
            className={styles.menuButton}
            aria-haspopup="dialog"
            aria-expanded={open}
            onClick={() => setOpen(true)}
          >
            <Icon name="menu" className={styles.menuIcon} />
            <span>{t('frame.menu')}</span>
          </button>
        </div>
        {track ? (
          <ol className={styles.groups} aria-label={t('top.steps', { track: t(`top.track.${track}`) })} data-track={track}>
            <li className={styles.track}>
              <Icon name={track === 'A' ? 'agent' : 'user'} className={styles.trackIcon} />
              <span>{t(`top.track.${track}`)}</span>
            </li>
            {Array.from({ length: STEPS }, (_, index) => index + 1).map((n) => {
              const state = step === null ? undefined : n < step ? 'done' : n === step ? 'now' : undefined;
              return (
                <li
                  key={n}
                  className={styles.group}
                  data-state={state}
                  aria-current={n === step ? 'step' : undefined}
                >
                  <span className={styles.groupMark} aria-hidden="true">
                    {n < (step ?? 0) ? <Icon name="check" className={styles.groupCheck} /> : n}
                  </span>
                  <span className={styles.groupName}>{t(`top.step.${n}`)}</span>
                  {state === 'done' ? <span className="visually-hidden"> {t('top.group.done')}</span> : null}
                </li>
              );
            })}
          </ol>
        ) : more ? (
          <MoreLine />
        ) : space ? (
          <div className={styles.space}>
            <span className={styles.spaceName}>
              {space.step ? `${space.name} · ${space.step}` : space.name}
            </span>
            {space.progress === null || space.progress === undefined ? null : (
              <span className={styles.progress} aria-hidden="true">
                <span className={styles.progressFill} style={{ inlineSize: `${space.progress}%` }} />
              </span>
            )}
          </div>
        ) : null}
      </header>
      <Modal open={open} onClose={() => setOpen(false)} title={t('frame.menu')}>
        <nav aria-label={t('frame.menu')} className={styles.menu}>
          {MENU.filter((item) => item.to !== '/videos' || hasGuides).map((item) => (
            <Link key={item.to} to={item.to} className={styles.menuItem} onClick={() => setOpen(false)}>
              {t(item.key)}
            </Link>
          ))}
          <button
            type="button"
            className={styles.menuItem}
            onClick={() => {
              setOpen(false);
              openGlossary();
            }}
          >
            {t('frame.menu.glossary')}
          </button>
          <button
            type="button"
            className={styles.menuItem}
            lang={other}
            onClick={() => {
              setOpen(false);
              void setLanguage(other);
            }}
          >
            {t('frame.menu.language')}
          </button>
        </nav>
      </Modal>
    </>
  );
}

/**
 * The line a "learn more" screen shows in place of the groups: it is optional, and the way back leads to the screen of
 * the main flow the visitor last stood on (the journey the portal keeps), or the start.
 */
function MoreLine() {
  const { t } = useTranslation();
  const location = useLocation();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const step = journey.data?.state.step;
  const back = DEFAULT_ROUTE.find((screen) => screen.id === step)?.path ?? '/';
  // A topic's screen says which topic it is and where in it (최종화면-구현계획 F3-6); the hub names only itself.
  const topic = topicOf(location.pathname);
  const at = topic ? topic.screens.findIndex((screen) => screen.path === location.pathname) : -1;
  return (
    <div className={styles.space}>
      {topic ? (
        <Link to={MORE_PATH} className={styles.moreName}>
          {t('top.more')}
        </Link>
      ) : (
        <span className={styles.moreName}>{t('top.more')}</span>
      )}
      {topic ? (
        <span className={styles.moreTopic}>
          {t(`more.topic.${topic.id}`)}
          {topic.screens.length > 1 ? ` · ${at + 1}/${topic.screens.length}` : ''}
          {topic.screens[at] ? ` · ${t(`more.name.${topic.screens[at].id}`)}` : ''}
        </span>
      ) : null}
      <Link to={back} className={styles.moreBack}>
        <Icon name="arrowLeft" className={styles.moreIcon} />
        {t('top.backToFlow')}
      </Link>
    </div>
  );
}
