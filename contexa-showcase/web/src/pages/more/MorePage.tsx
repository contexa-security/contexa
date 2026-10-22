import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useVisitor } from '../../api/queries';
import { AppHeader } from '../../components/AppHeader';
import { TermScope } from '../../components/common/Glossary';
import frame from '../../components/main/MainScreen.module.css';
import styles from './MorePage.module.css';

/** The topics of "learn more" in the design's order, each with where it starts and what kind of screen it is. */
const TOPICS = [
  { id: 'learning', to: '/intro/learning', kind: 'run' },
  { id: 'timing', to: '/try/timing/concept', kind: 'run' },
  { id: 'follow', to: '/try/follow', kind: 'record' },
  { id: 'approaches', to: '/intro/approaches', kind: 'explain' },
  { id: 'lab', to: '/lab', kind: 'run' },
  { id: 'benchmark', to: '/benchmark', kind: 'measured' },
  { id: 'adopt', to: '/adopt', kind: 'guide' },
] as const;

/**
 * The hub of "learn more" (최종화면-구현계획 F0-7, 설계서 더 알아보기): the screens of the site before the redesign,
 * grouped by question, all of them real runs and records. A topic walks its screens in order and ends back here.
 * The hub has no way back, no next screen and no main button (the top bar leads back to the flow), so it draws the
 * main flow's frame without its footer band (B-05): the same page, headline, intro and core.
 */
export default function MorePage() {
  const { t } = useTranslation();
  useVisitor();
  return (
    <>
      <AppHeader />
      <main id="main" className={frame.page}>
        <TermScope>
          <div className={frame.inner}>
            <header className={frame.head} data-zone="title" data-block>
              <h1 className={frame.title}>{t('more.title')}</h1>
              <p className={frame.intro} data-guide>
                {t('more.intro')}
              </p>
            </header>
            <div className={frame.core} data-zone="body">
              <ul className={styles.cards}>
                {TOPICS.map((topic, index) => (
                  <li
                    key={topic.id}
                    className={styles.item}
                    style={{ animationDelay: `calc(var(--more-step) * ${index})` }}
                  >
                    <Link to={topic.to} className={styles.card}>
                      <b className={styles.name}>{t(`more.topic.${topic.id}`)}</b>
                      <span className={styles.line}>{t(`more.topic.${topic.id}.line`)}</span>
                      <span className={styles.kind}>{t(`more.kind.${topic.kind}`)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </TermScope>
      </main>
    </>
  );
}
