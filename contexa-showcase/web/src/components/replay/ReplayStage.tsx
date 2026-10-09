import type { TFunction } from 'i18next';
import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { Layer } from '../../api/types';
import { count, seconds } from '../../journey/format';
import { ActionChip } from '../common/ActionChip';
import { Icon } from '../Icon';
import { RightMark } from '../journey/StepParts';
import styles from './ReplayStage.module.css';

/** The rows of a column in the order they light up; Contexa's comes last. */
const ROWS = ['gate', 'C1', 'C2', 'D'] as const;
type Row = (typeof ROWS)[number];

/** How long each rule row waits before it lights, and how often Contexa's deciding time is redrawn. */
const ROW_MS = 900;
const TICK_MS = 100;

/** One recorded run of a case, replayed as one column. */
export interface ReplayColumnData {
  readonly key: string;
  readonly title: string;
  /** The case's right answer in words. */
  readonly answer: string;
  /** A case of normal work: a rule that stops it halts the work. */
  readonly normal: boolean;
  readonly layers: readonly Layer[];
  /** Whether each approach answered the case right by the one scoring rule; an approach left out is neither. */
  readonly correct: Readonly<Partial<Record<string, boolean>>> | undefined;
  /** The measurement's line under the column ("measured 3 times, all the same"). */
  readonly measured: string;
}

interface ReplayStageProps {
  /** The source tag of the replayed runs and their measurement. */
  readonly source: ReactNode;
  readonly columns: readonly ReplayColumnData[];
}

/**
 * The replay of recorded runs (hook, D-35): a bar that says it is a replay with its source and a way to play it again,
 * then one column per run, every approach's recorded answer lit in order with right or wrong, Contexa's last after its
 * real deciding time. The first screen and the replay of a spent day's case use the same stage.
 */
export function ReplayStage({ source, columns }: ReplayStageProps) {
  const { t } = useTranslation();
  const [replay, setReplay] = useState(0);
  return (
    <>
      <div className={styles.replayBar}>
        <Icon name="play" className={styles.replayIcon} />
        <span>{t('hook.replay')}</span>
        {source}
        <span className={styles.again}>
          <ActionChip icon="refresh" size="sm" variant="open" onClick={() => setReplay((value) => value + 1)}>
            {t('hook.replayAgain')}
          </ActionChip>
        </span>
      </div>
      <div className={styles.columns} data-single={columns.length === 1 || undefined}>
        {columns.map((column) => (
          <Column key={`${column.key}-${replay}`} column={column} />
        ))}
      </div>
    </>
  );
}

/**
 * One case's recorded answers, lit in order, each with right or wrong; the perimeter, sign-in and permission row opens
 * into its two approaches when pressed.
 */
function Column({ column }: { readonly column: ReplayColumnData }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const layers = new Map(column.layers.map((layer) => [layer.control, layer]));
  const contexa = layers.get('D') ?? null;
  const decidedMs = contexa?.evidence.responseMs ?? 0;
  const [elapsed, setElapsed] = useState(() => (reducedMotion() ? Number.MAX_SAFE_INTEGER : 0));
  const [split, setSplit] = useState(false);
  const gateSame = layers.get('A')?.outcome === layers.get('B')?.outcome;

  useEffect(() => {
    if (elapsed >= ROW_MS * 3 + decidedMs) {
      return undefined;
    }
    const timer = window.setTimeout(() => setElapsed((value) => value + TICK_MS), TICK_MS);
    return () => window.clearTimeout(timer);
  }, [elapsed, decidedMs]);

  const lit = (row: Row) => elapsed >= (row === 'D' ? ROW_MS * 3 + decidedMs : ROW_MS * ROWS.indexOf(row));
  const showSplit = split || !gateSame;
  const right = (control: string) => (column.correct ? column.correct[control] : undefined);
  const titleId = `replay-${column.key}`;

  return (
    <section
      className={styles.column}
      data-side={column.normal ? 'owner' : 'attacker'}
      aria-labelledby={titleId}
    >
      <header className={styles.columnHead}>
        <h2 id={titleId} className={styles.columnTitle}>
          {column.title}
        </h2>
        <p className={styles.columnAnswer}>{column.answer}</p>
      </header>
      <ul className={styles.rows}>
        {showSplit ? (
          (['A', 'B'] as const).map((control) => (
            <li key={control} className={styles.row} data-row={control} data-lit={lit('gate') || undefined}>
              <span className={styles.rowName}>{t(`control.${control}.name`)}</span>
              <span className={styles.rowValue}>
                {lit('gate') ? answer(t, column.normal, layers.get(control)) : ''}
              </span>
              <span className={styles.rowMark}>
                {lit('gate') ? <RightMark right={right(control)} compactOnPhone /> : null}
              </span>
            </li>
          ))
        ) : (
          <li className={styles.row} data-row="gate" data-lit={lit('gate') || undefined}>
            <span className={styles.rowName}>
              {t('hook.row.gate')}
              <ActionChip icon="chevronDown" size="sm" expanded={false} onClick={() => setSplit(true)}>
                {t('hook.split')}
              </ActionChip>
            </span>
            <span className={styles.rowValue}>
              {lit('gate') ? answer(t, column.normal, layers.get('A')) : ''}
            </span>
            <span className={styles.rowMark}>
              {lit('gate') ? <RightMark right={right('A')} compactOnPhone /> : null}
            </span>
          </li>
        )}
        {(['C1', 'C2'] as const).map((control) => (
          <li key={control} className={styles.row} data-row={control} data-lit={lit(control) || undefined}>
            <span className={styles.rowName}>{t(`hook.row.${control}`)}</span>
            <span className={styles.rowValue}>
              {lit(control) ? answer(t, column.normal, layers.get(control)) : ''}
            </span>
            <span className={styles.rowMark}>
              {lit(control) ? <RightMark right={right(control)} compactOnPhone /> : null}
            </span>
          </li>
        ))}
        <li className={styles.row} data-row="D" data-lit={lit('D') || undefined} data-contexa="true">
          <span className={styles.rowName}>{t('hook.row.D')}</span>
          <span className={styles.rowValue}>
            {lit('D')
              ? contexaAnswer(t, language, contexa)
              : elapsed >= ROW_MS * 3
                ? t('hook.judging', { seconds: seconds(Math.min(elapsed - ROW_MS * 3, decidedMs)) })
                : ''}
          </span>
          <span className={styles.rowMark}>
            {lit('D') ? <RightMark right={right('D')} compactOnPhone /> : null}
          </span>
        </li>
      </ul>
      <p className={styles.measured}>{column.measured}</p>
    </section>
  );
}

/** A rule control's recorded answer: passed, or stopped (a real employee's work stopped with it). */
function answer(t: TFunction, normal: boolean, layer: Layer | undefined): string {
  if (!layer) {
    return '';
  }
  if (layer.outcome === 'DELIVERED') {
    return t('hook.passed');
  }
  return t(normal ? 'hook.halted' : 'hook.stopped');
}

/** Contexa's recorded decision and what it let out. */
function contexaAnswer(t: TFunction, language: string, layer: Layer | null): string {
  if (!layer) {
    return '';
  }
  const verdict = layer.verdict;
  const result =
    verdict === 'ALLOW' && layer.outcome === 'DELIVERED'
      ? t('hook.passed')
      : verdict === 'CHALLENGE'
        ? t('verdict.verify')
        : verdict === 'ESCALATE'
          ? t('verdict.review')
          : verdict === 'BLOCK'
            ? t('verdict.block')
            : t(layer.outcome === 'DELIVERED' ? 'hook.passed' : 'hook.stopped');
  return t('hook.withItems', { result, items: count(layer.evidence.deliveredItems, language) });
}

function reducedMotion(): boolean {
  return (
    typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}
