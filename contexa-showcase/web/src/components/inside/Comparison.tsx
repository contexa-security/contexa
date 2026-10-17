import { useId, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { AdverseLabel, BeforeSendView, UsualVsNow } from '../../api/anatomy';
import { COMPARED, membership, plainValue, type Compared } from '../../pages/try/experience';
import styles from '../../pages/try/Experience.module.css';
import { OriginalChip } from '../facts/OriginalChip';
import { Icon } from '../Icon';
import { plainLinesOf } from './promptSections';

type T = ReturnType<typeof useTranslation>['t'];

interface Row {
  readonly dimension: Compared;
  readonly state: 'same' | 'different' | 'unknown';
  readonly usual: string;
  readonly now: string;
  /** A v20 item's engine values (N-DEP-1, C-5), behind the "original" chip; null for a v19 item. */
  readonly original: string | null;
}

interface CompanyRow {
  readonly key: string;
  readonly text: string;
  readonly flagged: boolean;
  /** The engine's line behind the "original" chip; null for a row of the business database's words. */
  readonly original: string | null;
}

/** The prompt lines a v20 comparison is read from (portal SealedDeviations, N-DEP-1). */
const SEALED_LINES = ['DeviationsFromBaseline', 'SameAsBaseline'];

/** The usual of a v20 export size is its largest export, of a request rate its median per active hour. */
const USUAL_WORDS: Readonly<Record<string, string>> = { size: 'dim.items.upTo', rate: 'dim.rate.usual' };

interface ComparisonProps {
  readonly comparison: BeforeSendView;
  /** The heading level under the screen's or the window's own title. */
  readonly level: 'h2' | 'h3';
  /** A company record the screen shows as its own card above the others (try 2's approval), left out of the list. */
  readonly approval?: { readonly card: ReactNode; readonly leaveOut: string } | null;
}

/**
 * What the engine received, compared with the usual (e1-compare; the decision details' "received" tab shows the same):
 * the items that differ from the usual, usual then now, and the company records it flagged. The differences stand
 * out; the items that are the same and the records that flag nothing stay folded (D-41).
 */
export function Comparison({ comparison, level: Heading, approval = null }: ComparisonProps) {
  const { t } = useTranslation();
  const usualId = useId();
  const companyId = useId();
  const rows = COMPARED.map((dimension) => compareRow(t, dimension, comparison)).filter(
    (row): row is Row => row !== null,
  );
  const different = rows.filter((row) => row.state === 'different');
  const rest = rows.filter((row) => row.state !== 'different');
  const company = companyRows(t, comparison);
  const flagged = company.filter((row) => row.flagged);
  const unflagged = company.filter((row) => !row.flagged && row.key !== approval?.leaveOut);
  return (
    <div className={styles.compareGrid}>
      <section className={styles.panel} aria-labelledby={usualId}>
        <Heading id={usualId} className={styles.panelTitle}>
          {t('e1.compare.differentTitle', { n: comparison.departureCount })}
        </Heading>
        <ul className={styles.diffs}>
          {different.map((row) => (
            <li key={row.dimension} className={styles.diff}>
              <span className={styles.diffName}>{t(`dim.${row.dimension}`)}</span>
              <span className={styles.diffUsual}>
                <span className={styles.diffLabel}>{t('e1.compare.usual')}</span>
                {row.usual || t('dim.unknown')}
              </span>
              <Icon name="arrowRight" className={styles.diffArrow} />
              <span className={styles.diffNow}>
                <span className={styles.diffLabel}>{t('e1.compare.now')}</span>
                {row.now || '-'}
                {row.original ? <OriginalChip text={row.original} /> : null}
              </span>
            </li>
          ))}
        </ul>
        {rest.length > 0 ? (
          <details className={styles.more}>
            <summary>
              {t('e1.compare.rest', {
                names: rest.map((row) => t(`dim.${row.dimension}`)).join(' · '),
              })}
            </summary>
            <ul className={styles.restRows}>
              {rest.map((row) => (
                <li key={row.dimension}>
                  <span className={styles.restName}>{t(`dim.${row.dimension}`)}</span>
                  <span>{row.now || '-'}</span>
                  <span className={styles.restState}>{t(`dim.${row.state}`)}</span>
                  {row.original ? <OriginalChip text={row.original} /> : null}
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </section>
      <section className={styles.panel} aria-labelledby={companyId}>
        <Heading id={companyId} className={styles.panelTitle}>
          {approval
            ? t('e2.compare.companyTitle')
            : t('e1.compare.companyTitle', { n: comparison.companyAdverseCount })}
        </Heading>
        {approval?.card ?? null}
        {flagged.length > 0 ? (
          <ul className={styles.flags}>
            {flagged.map((row) => (
              <li key={row.key} className={styles.flagRow}>
                <Icon name="cross" className={styles.flagIcon} />
                {row.text}
                {row.original ? <OriginalChip text={row.original} /> : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className={styles.lead}>{t('e1.compare.noFlag')}</p>
        )}
        {unflagged.length > 0 ? (
          <details className={styles.more}>
            <summary>{t('e1.compare.otherRecords')}</summary>
            <ul className={styles.restRows}>
              {unflagged.map((row) => (
                <li key={row.key}>{row.text}</li>
              ))}
            </ul>
          </details>
        ) : null}
      </section>
    </div>
  );
}

/**
 * One compared item: the baseline's values from the prompt line, the current value, and the engine's own label. The
 * browser and the system make one device item (a v20 step compares the device as one, N-DEP-1); hours are
 * listed in clock order. A v20 item is named in plain words, its engine values behind the "original"
 * chip (C-5).
 */
function compareRow(t: T, dimension: Compared, comparison: BeforeSendView): Row | null {
  const rows = (dimension === 'device' ? ['operatingSystem', 'browser', 'device'] : [dimension])
    .map((key) => ({ key, row: comparison.usualVsNow.find((candidate) => candidate.dimension === key) }))
    .filter((entry): entry is { key: string; row: UsualVsNow } => entry.row !== undefined);
  if (rows.length === 0) {
    return null;
  }
  const states = rows.map((entry) => membership(entry.row.inUsual));
  const state = states.includes('different') ? 'different' : states.includes('unknown') ? 'unknown' : 'same';
  const usual = rows
    .map((entry) => {
      const values = [...(comparison.usual[entry.key]?.values ?? [])];
      if (entry.key === 'accessHour' && values.every((value) => /^\d+$/.test(value))) {
        values.sort((left, right) => Number(left) - Number(right));
      }
      return [...new Set(values.map((value) => usualWords(t, entry.key, value)))].join(' · ');
    })
    .filter((text) => text.length > 0)
    .join(' · ');
  const now = rows
    .map((entry) => (entry.row.now === null ? '' : plainValue(t, entry.key, entry.row.now)))
    .filter((text) => text.length > 0)
    .join(' · ');
  const sealed = rows.some((entry) => entry.row.labels.some((label) => SEALED_LINES.includes(label)));
  return { dimension, state, usual, now, original: sealed ? originalOf(rows, comparison) : null };
}

/** One usual value in plain words; of a v20 size or rate the count it is (USUAL_WORDS). */
function usualWords(t: T, key: string, value: string): string {
  const words = USUAL_WORDS[key];
  return words !== undefined && /^[0-9.,]+$/.test(value) ? t(words, { n: value }) : plainValue(t, key, value);
}

/** The engine's own values of a v20 item: its line with the current value, and the sealed usual. */
function originalOf(
  rows: readonly { readonly key: string; readonly row: UsualVsNow }[],
  comparison: BeforeSendView,
): string {
  return rows
    .map((entry) => {
      const usual = comparison.usual[entry.key];
      const now = `${entry.row.labels.join(', ')} · ${entry.row.now ?? '-'}`;
      return usual ? `${now} | ${usual.label} · ${usual.values.join(', ')}` : now;
    })
    .join(' / ');
}

/**
 * The company records: a v20 decision's policy its PolicySatisfied states as not met (N-DEP-2), the approval
 * requirement as the engine read it, then the business database's facts.
 */
function companyRows(t: T, comparison: BeforeSendView): readonly CompanyRow[] {
  const flagged = new Set(comparison.companyAdverse.map((label) => label.label));
  return [
    ...comparison.companyAdverse
      .filter((label) => label.label === 'policysatisfied' && label.met)
      .map((label) => policyRow(t, label)),
    ...(comparison.company['approvalRequired'] === true
      ? [
          {
            key: 'approvalRequired',
            text: t('e1.compare.approvalRequired'),
            flagged: flagged.has('approvalrequired'),
            original: null,
          },
        ]
      : []),
    ...comparison.businessFacts.map((fact) => ({
      key: fact.code,
      text: t(`fact.${fact.code}`, { value: fact.value ?? '' }),
      flagged: fact.code === 'NO_APPROVAL' && flagged.has('approvalmissing'),
      original: null,
    })),
  ];
}

/** The unmet policy in the fact card's plain words for its line, the line behind "original". */
function policyRow(t: T, label: AdverseLabel): CompanyRow {
  const line = label.values[0] === undefined ? null : `PolicySatisfied: ${label.values[0]}`;
  const note = line === null ? undefined : plainLinesOf('V20_BLOCKS', 'DECISION_FACTS', [line])[0]?.key;
  return {
    key: 'policysatisfied',
    text: t(note ?? 'adverse.policysatisfied'),
    flagged: true,
    original: line,
  };
}
