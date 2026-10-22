import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { Icon } from '../../components/Icon';
import styles from './SummaryEndPage.module.css';

/** The three ways on from the end of the flow (화면재편-기획안 7절 5-4). */
const PATHS = [
  { to: '/lab', key: 'lab', icon: 'search' },
  { to: '/benchmark', key: 'benchmark', icon: 'chart' },
  { to: '/adopt', key: 'adopt', icon: 'code' },
] as const;

/**
 * The end of the main flow (5-4, a new screen): one choice among three cards, each a space outside the flow with its
 * own purpose. The cards are the screen's action, so there is no further main button.
 */
export default function SummaryEndPage() {
  const { t } = useTranslation();
  return (
    <RouteScreen title={t('screen.5-4.title')} purpose={t('screen.5-4.guide')}>
      <ul className={styles.paths} data-count="exempt">
        {PATHS.map((path) => (
          <li key={path.key}>
            <Link to={path.to} className={styles.path}>
              <Icon name={path.icon} className={styles.icon} />
              <span className={styles.name}>{t(`screen.5-4.${path.key}`)}</span>
              <span className={styles.line}>{t(`screen.5-4.${path.key}.line`)}</span>
            </Link>
          </li>
        ))}
      </ul>
    </RouteScreen>
  );
}
