import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { ALL_ITEMS, groupOf } from '../routes';
import { Icon, Modal, type UxIconName } from '../ui';
import styles from './Shell.module.css';

interface Result {
  readonly key: string;
  readonly label: string;
  readonly where: string;
  readonly to: string;
  readonly icon: UxIconName;
}

/** A run ID as the portal writes it (`run-04cdd89264f7`). */
const RUN_ID = /^run-[0-9a-f]{6,}$/i;

/**
 * The search of the top bar (기획안 4.2, `Ctrl K`): the menus by name and a run ID straight to its decision details.
 * The security terms join from the glossary file (I-8). Arrow keys move, Enter opens, Escape closes.
 */
export function SearchDialog({ open, onClose }: { readonly open: boolean; readonly onClose: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const listId = useId();
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  // Each opening is a fresh dialog (the frame gives it a new key), so the query starts empty; the field takes the focus
  // once the dialog is shown.
  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const timer = window.setTimeout(() => input.current?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [open]);
  const results = useMemo<readonly Result[]>(() => {
    const words = query.trim().toLowerCase();
    const found: Result[] = [];
    if (RUN_ID.test(words)) {
      found.push({
        key: `run-${words}`,
        label: t('ux.search.run', { id: words }),
        where: t('ux.menu.runs'),
        to: `/runs/${encodeURIComponent(words)}`,
        icon: 'file-search',
      });
    }
    for (const item of ALL_ITEMS) {
      const label = t(`ux.menu.${item.id}`);
      const group = groupOf(item);
      const where = group ? t(`ux.nav.group.${group.id}`) : t('ux.nav.foot');
      if (!words || label.toLowerCase().includes(words) || where.toLowerCase().includes(words)) {
        found.push({ key: item.id, label, where, to: item.path, icon: item.icon });
      }
    }
    return found;
  }, [query, t]);
  const go = (result: Result | undefined) => {
    if (result) {
      onClose();
      navigate(result.to);
    }
  };
  const keys = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      setActive((at) => (results.length === 0 ? 0 : (at + step + results.length) % results.length));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      go(results[active]);
    }
  };
  const optionId = (index: number) => `${listId}-option-${index}`;
  return (
    <Modal open={open} onClose={onClose} title={t('ux.search.title')} size="sm">
      <div className={styles.search}>
        <div className={styles.searchField}>
          <Icon name="search" size="md" />
          <input
            ref={input}
            type="search"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={results[active] ? optionId(active) : undefined}
            aria-label={t('ux.search.title')}
            placeholder={t('ux.search.placeholder')}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActive(0);
            }}
            onKeyDown={keys}
            className={styles.searchInput}
          />
        </div>
        <ul id={listId} role="listbox" aria-label={t('ux.search.title')} className={styles.searchList}>
          {results.map((result, index) => (
            <li
              key={result.key}
              id={optionId(index)}
              role="option"
              aria-selected={index === active}
              className={styles.searchOption}
              onMouseEnter={() => setActive(index)}
              onClick={() => go(result)}
            >
              <Icon name={result.icon} size="md" />
              <span className={styles.searchLabel}>{result.label}</span>
              <span className={styles.searchWhere}>{result.where}</span>
            </li>
          ))}
        </ul>
        {results.length === 0 ? <p className={styles.searchEmpty}>{t('ux.search.empty')}</p> : null}
        <p className={styles.searchHint}>{t('ux.search.hint')}</p>
      </div>
    </Modal>
  );
}
