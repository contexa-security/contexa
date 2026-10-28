import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { GuidePreview } from '../../components/guide/GuidePreview';
import { ChooseScreen } from '../../components/main/ChooseScreen';
import { Icon } from '../../components/Icon';
import { nextScreen } from '../../journey/journey';
import styles from './OpeningPage.module.css';

/**
 * 1-1, the landing (docs/showcase/첫화면-선택형-체험-구현계획 NW-2, 사용자 지시 2026-10-27): the visitor does not know
 * Contexa and is not used to a "demo", so the screen says in plain words what Contexa is, in one strong question and one
 * line, what the visitor will do here in one short line, and gives one way in, "데모 시작하기". The choice of a track
 * is the next screen's.
 */
export default function OpeningPage() {
  const { t } = useTranslation();
  const start = nextScreen('DEFAULT', '/')?.path ?? '/choose';
  return (
    <ChooseScreen center title={t('main.1-1.title')} intro={t('main.1-1.intro')}>
      <p className={styles.purpose} data-guide="start-purpose">
        {t('main.1-1.purpose')}
      </p>
      <div className={styles.go}>
        <Link to={start} className={styles.start} data-main>
          {t('main.1-1.cta')}
          <Icon name="arrowRight" className={styles.startIcon} />
        </Link>
        <p className={styles.meta}>{t('main.1-1.meta')}</p>
        {/* 가이드영상-제작기획안.md 4.1절: the start video, for a visitor who is new here, beside the way in. */}
        <GuidePreview id="start" variant="start" />
      </div>
    </ChooseScreen>
  );
}
