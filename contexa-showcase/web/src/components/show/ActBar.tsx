import { useTranslation } from 'react-i18next';
import styles from './ActBar.module.css';

interface ActBarProps {
  /** The act the visitor is in, 1 to 3, or 0 before the first. */
  readonly act: 0 | 1 | 2 | 3;
}

/** Where the visitor is in the three acts and how much is left (docs/showcase/화면설계서.md 1.4). */
export function ActBar({ act }: ActBarProps) {
  const { t } = useTranslation();
  return (
    <ol className={styles.bar} aria-label={t('show.act.label')}>
      {([1, 2, 3] as const).map((number) => {
        const state = number < act ? 'done' : number === act ? 'current' : 'next';
        return (
          <li
            key={number}
            className={styles.act}
            data-state={state}
            aria-current={state === 'current' ? 'step' : undefined}
          >
            {t(`show.act.${number}`)}
          </li>
        );
      })}
    </ol>
  );
}
