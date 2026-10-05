import { useTranslation } from 'react-i18next';
import type { CombinationCell } from '../api/types';
import { ITEMS, SLOTS } from '../domain/explore';
import { VERDICTS } from '../domain/verdict';
import styles from './BoundaryMap.module.css';

interface BoundaryMapProps {
  readonly cells: readonly CombinationCell[];
  readonly selected: string;
  readonly onSelect: (cell: CombinationCell) => void;
}

/**
 * Deck p.13: Contexa's real run of each time and count, for the chosen employee, ticket and device. A cell is filled
 * only by a stored real run; the others say they have not been run.
 */
export function BoundaryMap({ cells, selected, onSelect }: BoundaryMapProps) {
  const { t } = useTranslation();
  const byKey = new Map(cells.map((cell) => [`${cell.slot}.${cell.items}`, cell]));
  return (
    <table className={styles.map}>
      <caption className={styles.caption}>{t('explore.map')}</caption>
      <thead>
        <tr>
          <th scope="col" className={styles.corner}>
            <span className="visually-hidden">{t('explore.items')}</span>
          </th>
          {SLOTS.map((slot) => (
            <th key={slot} scope="col" className={styles.slot}>
              {t(`explore.slot.${slot}`)}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {[...ITEMS].reverse().map((items) => (
          <tr key={items}>
            <th scope="row" className={styles.items}>
              {t(`explore.items.${items}`)}
            </th>
            {SLOTS.map((slot) => {
              const cell = byKey.get(`${slot}.${items}`);
              if (!cell) {
                return <td key={slot} />;
              }
              const verdict = cell.recorded && cell.engineVerdict ? cell.engineVerdict : null;
              const word = verdict ? t(VERDICTS[verdict].labelKey) : t('explore.notRun');
              return (
                <td key={slot}>
                  <button
                    type="button"
                    className={styles.cell}
                    data-verdict={verdict ?? 'NONE'}
                    aria-pressed={cell.key === selected}
                    aria-label={`${t(`explore.slot.${slot}`)} · ${t(`explore.items.${items}`)} · ${word}`}
                    onClick={() => onSelect(cell)}
                  >
                    {word}
                  </button>
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
