import { useId, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Icon } from '../Icon';
import { Modal } from '../common/Modal';
import type { InsideCellId, InsideCellState } from './insideCells';
import styles from './InsidePanel.module.css';

export type { InsideCellState } from './insideCells';

export interface InsideCell {
  readonly id: InsideCellId;
  readonly state: InsideCellState;
  /** The cell's one-line value, as the record gives it (for example "3 differences"). */
  readonly summary?: ReactNode;
  /** What opens below the cell when it is clicked. */
  readonly detail?: ReactNode;
}

const ICONS = { waiting: 'dash', active: 'clock', done: 'check', decision: 'key' } as const;

/**
 * The inside-view panel (panel slide): the nine cells light up in order while the request is analysed, and a clicked
 * cell opens below itself (not a modal). On phones the panel is a nine-cell strip at the bottom that opens as a sheet.
 */
export function InsidePanel({ cells }: { readonly cells: readonly InsideCell[] }) {
  const { t } = useTranslation();
  const [sheet, setSheet] = useState(false);
  return (
    <>
      <aside className={styles.panel} aria-label={t('inside.title')}>
        <h2 className={styles.title}>{t('inside.title')}</h2>
        <CellList cells={cells} />
      </aside>
      <div className={styles.strip} data-inside-strip>
        <button type="button" className={styles.stripButton} onClick={() => setSheet(true)}>
          <span className={styles.visuallyHidden}>{t('inside.openStrip')}</span>
          {cells.map((cell, index) => (
            <span key={cell.id} className={styles.stripCell} data-state={cell.state} aria-hidden="true">
              {index + 1}
            </span>
          ))}
        </button>
      </div>
      <Modal open={sheet} onClose={() => setSheet(false)} title={t('inside.title')}>
        <CellList cells={cells} />
      </Modal>
    </>
  );
}

function CellList({ cells }: { readonly cells: readonly InsideCell[] }) {
  const { t } = useTranslation();
  const [opened, setOpened] = useState<InsideCellId | null>(null);
  const prefix = useId();
  return (
    <ol className={styles.cells}>
      {cells.map((cell, index) => {
        const open = opened === cell.id;
        const detailId = `${prefix}-${cell.id}`;
        const head = (
          <>
            <span className={styles.number}>{index + 1}</span>
            <span className={styles.name}>{t(`inside.cell.${cell.id}`)}</span>
            <span className={styles.state} data-state={cell.state}>
              <Icon name={ICONS[cell.state]} />
              <span className={styles.visuallyHidden}>{t(`inside.state.${cell.state}`)}</span>
            </span>
            {cell.summary ? <span className={styles.summary}>{cell.summary}</span> : null}
          </>
        );
        return (
          <li key={cell.id} className={styles.cell} data-state={cell.state}>
            {cell.detail ? (
              <button
                type="button"
                className={styles.head}
                aria-expanded={open}
                aria-controls={detailId}
                onClick={() => setOpened(open ? null : cell.id)}
              >
                {head}
              </button>
            ) : (
              <div className={styles.head}>{head}</div>
            )}
            {cell.detail && open ? (
              <div id={detailId} className={styles.detail}>
                {cell.detail}
              </div>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}

interface DecisionDetailProps {
  /** The reason in plain words: the fixed Korean of a contract sentence, or a plain sentence from the values. */
  readonly plain: ReactNode;
  /** The engine's original reasoning, behind the "original" tag. */
  readonly original: string | null;
  /** Cited evidence kinds the engine wrote (baseline, sensitivity, authorization, resource, session, approval). */
  readonly cited: readonly string[];
  readonly riskScore: number | null;
  readonly confidence: number | null;
  /** The core inspector's adverse conditions: how many the prompt met and their names. */
  readonly inspector: {
    readonly met: number;
    readonly total: number;
    readonly names: readonly string[];
  } | null;
}

const REFS = new Set(['baseline', 'sensitivity', 'authorization', 'resource', 'session', 'approval']);

/** The decision cell opened (panel slide): reason, cited evidence, risk and confidence, the inspector's conditions. */
export function DecisionDetail({
  plain,
  original,
  cited,
  riskScore,
  confidence,
  inspector,
}: DecisionDetailProps) {
  const { t } = useTranslation();
  const [showOriginal, setShowOriginal] = useState(false);
  return (
    <div className={styles.decision}>
      <p className={styles.plain}>
        {plain}
        {original ? (
          <button
            type="button"
            className={styles.originalTag}
            aria-expanded={showOriginal}
            onClick={() => setShowOriginal((value) => !value)}
          >
            {t('source.original')}
          </button>
        ) : null}
      </p>
      {showOriginal && original ? <p className={styles.original}>{original}</p> : null}
      {cited.length > 0 ? (
        <div className={styles.cited}>
          <span className={styles.citedTitle}>{t('inside.cited')}</span>
          <ul className={styles.refs}>
            {cited.map((ref) => (
              <li key={ref} className={styles.ref}>
                {REFS.has(ref) ? t(`inside.ref.${ref}`) : ref}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <dl className={styles.scores}>
        <Score label={t('inside.risk')} value={riskScore} />
        <Score label={t('inside.confidence')} value={confidence} />
      </dl>
      {inspector ? (
        <p className={styles.inspector}>
          {t('inside.inspector', { met: inspector.met, total: inspector.total })}
          {inspector.names.length > 0 ? ` · ${inspector.names.join(', ')}` : ''}
        </p>
      ) : null}
    </div>
  );
}

function Score({ label, value }: { readonly label: string; readonly value: number | null }) {
  const { t } = useTranslation();
  return (
    <div className={styles.score}>
      <dt>{label}</dt>
      <dd>
        {value === null ? (
          t('inside.noValue')
        ) : (
          <>
            <meter min={0} max={1} value={value} className={styles.meter} />
            <span className={styles.scoreValue}>{value}</span>
          </>
        )}
      </dd>
    </div>
  );
}
