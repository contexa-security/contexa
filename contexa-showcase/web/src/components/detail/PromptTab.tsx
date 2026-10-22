import type { TFunction } from 'i18next';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { DecisionAnatomyView } from '../../api/anatomy';
import {
  useOtherBundle,
  useRunFacts,
  useRunQuality,
  type BundleSide,
  type FactBlock,
  type FactSufficiency,
  type OtherBundleView,
  type PromptFact,
  type QualityRibbonView,
} from '../../api/promptQuality';
import { count } from '../../journey/format';
import {
  blockOfLine,
  CHUNKS,
  compareOffered,
  factKey,
  factNoteKey,
  factsOf,
  FOLDS,
  ribbonHolds,
  ribbonLines,
} from '../facts/factWords';
import { ActionChip } from '../common/ActionChip';
import { Icon } from '../Icon';
import { StateScreen } from '../StateScreen';
import { TabFrame, type TabProps } from './TabFrame';
import styles from './DecisionDetail.module.css';

/** What the chooser offers: one part of the text sent to the AI, or the same situation under another bundle. */
type Part = FactBlock | 'compare';

/** A part's facts shown at a time; a longer part goes by pages (구현계획 5절: a table screen is paged, not lengthened). */
const PAGE = 4;

/** A line's plain words in the redesign's terms: the prompt screen's note under the tab's own key. */
function plainKey(key: string): string {
  return key.replace(/^prompt\.plain\./, 'detail.r7.plain.');
}

/** The action sources the sufficiency line names in plain words; any other source is "another value". */
const NAMED_SOURCES: ReadonlySet<string> = new Set(['protectableMethod', 'httpMethod', 'method']);

/** The grade and causes of a usual-pattern line whose evidence is below strong, in plain words (N-UI-1). */
function sufficiencyWords(t: TFunction, sufficiency: FactSufficiency): string {
  const causes = sufficiency.causes.map((cause) => {
    if (cause.kind !== 'ACTION_INFERRED') {
      return t(`detail.r7.sufficiency.${cause.kind}`, { n: cause.count, of: cause.of });
    }
    const named = cause.from !== null && NAMED_SOURCES.has(cause.from) ? cause.from : 'other';
    const key =
      cause.count === cause.of
        ? 'detail.r7.sufficiency.ACTION_INFERRED_ALL'
        : 'detail.r7.sufficiency.ACTION_INFERRED';
    return t(key, { n: cause.count, of: cause.of, from: t(`detail.r7.sufficiency.from.${named}`) });
  });
  const cautions =
    sufficiency.cautions > 0 ? [t('detail.r7.sufficiency.cautions', { n: sufficiency.cautions })] : [];
  const parts = [...causes, ...cautions];
  const grade = t(`detail.r7.sufficiency.${sufficiency.grade}`);
  return parts.length > 0 ? `${grade}: ${parts.join(' · ')}` : grade;
}

/**
 * The text sent to the AI (RO-1): the prompt screen's fact cards and its comparison with another bundle, moved here.
 * One chooser picks a part of the text (the five parts in the order the AI reads them, then the past records, the
 * outside text and a second pass when there is one) or the same situation under another bundle, when the server found
 * such a request. A part is one table: each fact's plain name and source, then its plain words where it has them and
 * the line's value as it was sent. Above the parts: the official inspection's counts and the core inspector's adverse
 * conditions. Every value is the server's reading of this request's sealed text.
 */
export function PromptTab({ view, runId, step }: TabProps & { readonly view: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const facts = useRunFacts(runId, step);
  const quality = useRunQuality(runId, step);
  const other = useOtherBundle(runId, step).data ?? null;
  const [part, setPart] = useState<Part>('DECISION_FACTS');
  const [page, setPage] = useState(0);
  // The line a check led to (P-21), marked in its part's table.
  const [target, setTarget] = useState<number | null>(null);
  const chooserId = useId();
  if (facts.isPending || quality.isPending) {
    return <StateScreen kind="loading" />;
  }
  const shown = facts.data?.available ? facts.data : null;
  const offered = compareOffered(other);
  const parts: readonly Part[] = [
    ...(shown
      ? [...CHUNKS, ...FOLDS.filter((block) => block !== 'SECOND_PASS' || factsOf(shown, block).length > 0)]
      : []),
    ...(offered ? (['compare'] as const) : []),
  ];
  const chosen: Part | null = parts.includes(part) ? part : (parts[0] ?? null);
  const ribbon = quality.data?.available ? (quality.data.ribbon ?? null) : null;
  const reason = facts.data?.reason ?? quality.data?.reason ?? 'other';
  // P-21: the first line without a source, one press away: its part, the page that holds it, the row marked.
  const missing = shown ? ribbonLines(quality.data ?? null, shown).source : null;
  const toMissing =
    shown && missing !== null
      ? () => {
          const block = blockOfLine(shown, missing);
          if (!block) {
            return;
          }
          const at = factsOf(shown, block).findIndex((entry) => entry.line === missing);
          setPart(block);
          setPage(Math.max(0, Math.floor(at / PAGE)));
          setTarget(missing);
        }
      : null;

  return (
    <TabFrame source={t(chosen === 'compare' ? 'detail.r7.prompt.sourceCompare' : 'detail.r7.prompt.source')}>
      {shown ? null : (
        <p className={styles.line} data-state="no-facts">
          {t(`detail.r7.prompt.reason.${reason}`, { defaultValue: t('detail.r7.prompt.reason.other') })}
        </p>
      )}
      {chosen !== 'compare' && shown ? <Checks view={view} ribbon={ribbon} onMissing={toMissing} /> : null}
      {chosen ? (
        <div className={styles.chooser}>
          <label htmlFor={chooserId} className={styles.label}>
            {t('detail.r7.prompt.choose')}
          </label>
          <select
            id={chooserId}
            className={styles.select}
            value={chosen}
            onChange={(event) => {
              setPart(event.target.value as Part);
              setPage(0);
              setTarget(null);
            }}
          >
            {parts.map((entry) => (
              <option key={entry} value={entry}>
                {t(`detail.r7.prompt.block.${entry}`)}
              </option>
            ))}
          </select>
          <p className={styles.aside}>{t(`detail.r7.prompt.what.${chosen}`)}</p>
        </div>
      ) : null}
      {chosen === 'compare' && other ? <Compare view={other} /> : null}
      {chosen && chosen !== 'compare' && shown ? (
        <FactTable
          block={chosen}
          facts={factsOf(shown, chosen)}
          page={page}
          onPage={setPage}
          target={target}
        />
      ) : null}
    </TabFrame>
  );
}

/**
 * How the text was checked: the official inspection's counts as the server gave them (facts with a source, facts that
 * match their source, contradictions, what it does not know) and how many of the core inspector's adverse conditions
 * the text met, with their names. A missing source is named in words, with the way to its line (P-21).
 */
function Checks({
  view,
  ribbon,
  onMissing,
}: {
  readonly view: DecisionAnatomyView;
  readonly ribbon: QualityRibbonView | null;
  readonly onMissing: (() => void) | null;
}) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const holds = ribbon ? ribbonHolds(ribbon) : null;
  const met = view.juxtaposition.coreAdverseLabels
    .filter((label) => label.met)
    .map((label) =>
      t(`detail.r7.adverse.${label.label}`, {
        defaultValue: t(`adverse.${label.label}`, { defaultValue: label.label }),
      }),
    );
  const mark = (ok: boolean | null) => (
    <span className={styles.mark} data-ok={ok === null ? undefined : ok}>
      <Icon name={ok === null ? 'clock' : ok ? 'check' : 'cross'} />
      <span className="visually-hidden">
        {t(
          ok === null
            ? 'detail.r7.prompt.check.pending'
            : ok
              ? 'detail.r7.prompt.check.ok'
              : 'detail.r7.prompt.check.failed',
        )}
      </span>
    </span>
  );
  return (
    <ul className={styles.inline} aria-label={t('detail.r7.prompt.check.title')}>
      {ribbon && holds ? (
        <>
          <li className={styles.value} data-item="source">
            {holds.source === false ? (
              <span className={styles.mark} data-ok={false}>
                <Icon name="cross" />
                {t('detail.r7.prompt.check.sourceMissing')}
              </span>
            ) : (
              mark(holds.source)
            )}
            {t('detail.r7.prompt.check.source', { n: ribbon.withSource, total: ribbon.facts })}
            {holds.source === false && onMissing ? (
              <ActionChip icon="arrowRight" size="sm" onClick={onMissing}>
                {t('detail.r7.prompt.check.toMissing')}
              </ActionChip>
            ) : null}
          </li>
          {ribbon.factAccuracy?.total === 0 ? (
            // The inspection compared no fact with its source: nothing is shown as matching.
            <li data-item="accuracy">{t('detail.r7.prompt.check.accuracyNone')}</li>
          ) : (
            <li className={styles.value} data-item="accuracy">
              {mark(holds.accuracy)}
              {ribbon.factAccuracy === null
                ? t('detail.r7.prompt.check.accuracyPending')
                : t('detail.r7.prompt.check.accuracy', {
                    n: ribbon.factAccuracy.matched,
                    total: ribbon.factAccuracy.total,
                  })}
            </li>
          )}
          <li className={styles.value} data-item="contradictions">
            {mark(holds.contradictions)}
            {ribbon.contradictions === null
              ? t('detail.r7.prompt.check.contradictionsPending')
              : t('detail.r7.prompt.check.contradictions', { n: count(ribbon.contradictions, language) })}
          </li>
          <li data-item="unknown">
            {t('detail.r7.prompt.check.unknown', { n: count(ribbon.unknown, language) })}
          </li>
        </>
      ) : (
        <li>{t('detail.r7.prompt.check.none')}</li>
      )}
      {/* A decision whose inspector reads no adverse conditions (v21) states no count of them. */}
      {view.juxtaposition.adverseChecked > 0 ? (
        <li className={styles.wide} data-item="adverse">
          {t('detail.r7.prompt.check.adverse', {
            total: count(view.juxtaposition.adverseChecked, language),
            met: count(view.juxtaposition.adverseMet, language),
          })}
          {met.length > 0 ? ` · ${met.join(', ')}` : ''}
        </li>
      ) : null}
    </ul>
  );
}

interface FactTableProps {
  readonly block: FactBlock;
  readonly facts: readonly PromptFact[];
  readonly page: number;
  readonly onPage: (page: number) => void;
  /** The line a check led to, marked (P-21). */
  readonly target?: number | null;
}

/**
 * One part's facts as one table, a page at a time: the fact's plain name and source, its plain words and the value as
 * it was sent; the earlier and later pages one press away.
 */
function FactTable({ block, facts, page, onPage, target = null }: FactTableProps) {
  const { t } = useTranslation();
  if (facts.length === 0) {
    return <p className={styles.line}>{t('detail.r7.prompt.noFacts')}</p>;
  }
  const pages = Math.ceil(facts.length / PAGE);
  const at = Math.min(page, pages - 1);
  const rows = facts.slice(at * PAGE, at * PAGE + PAGE);
  return (
    <div className={styles.group}>
      <table className={styles.table} aria-label={t(`detail.r7.prompt.block.${block}`)}>
        <thead>
          <tr>
            <th scope="col" className={styles.nameCell}>
              {t('detail.r7.prompt.col.fact')}
            </th>
            <th scope="col">{t('detail.r7.prompt.col.value')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((fact) => {
            const note = factNoteKey(block, fact);
            return (
              <tr key={fact.line} data-line={fact.line} data-target={fact.line === target || undefined}>
                <th scope="row" className={styles.nameCell}>
                  <span className={styles.item}>
                    <span>{t(`fact.label.${factKey(fact.label)}`)}</span>
                    <span className={styles.from}>{t(`fact.source.${fact.source ?? 'NONE'}`)}</span>
                  </span>
                </th>
                <td>
                  <span className={styles.item}>
                    {note ? <span>{t(plainKey(note))}</span> : null}
                    <code className={`${styles.original} ${styles.clamp}`} data-original>
                      {fact.value}
                    </code>
                    {fact.sufficiency ? (
                      <span className={styles.from} data-sufficiency={fact.sufficiency.grade}>
                        {sufficiencyWords(t, fact.sufficiency)}
                      </span>
                    ) : null}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className={styles.aside}>{t('detail.r7.prompt.clamped')}</p>
      {pages > 1 ? (
        <div className={styles.pager} role="group" aria-label={t('detail.r7.prompt.pages')}>
          <ActionChip icon="arrowLeft" size="sm" disabled={at === 0} onClick={() => onPage(at - 1)}>
            {t('detail.r7.prompt.previousPage')}
          </ActionChip>
          <span className={styles.label}>{t('detail.r7.prompt.page', { page: at + 1, pages })}</span>
          <ActionChip icon="arrowRight" size="sm" disabled={at >= pages - 1} onClick={() => onPage(at + 1)}>
            {t('detail.r7.prompt.nextPage')}
          </ActionChip>
        </div>
      ) : null}
    </div>
  );
}

/**
 * The same situation under another bundle (U-2): not the same request, but a request of the same situation and
 * conditions sent with the other prompt bundle, side by side with this one, and the server's ordered line counts of
 * both texts when it has them. Each side names its bundle and record number as they are.
 */
function Compare({ view }: { readonly view: OtherBundleView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  if (!view.current || !view.other) {
    return null;
  }
  const lines = view.lines ?? null;
  return (
    <>
      <div className={styles.group} data-block>
        <p className={styles.line}>{t('detail.r7.prompt.compare.lead')}</p>
        {lines ? (
          <p className={styles.line} data-lines>
            {t('detail.r7.prompt.compare.lines', {
              before: lines.before,
              beforeLines: count(lines.beforeLines, language),
              after: lines.after,
              afterLines: count(lines.afterLines, language),
            })}
          </p>
        ) : null}
      </div>
      <div className={styles.sides}>
        <Side side={view.current} name={t('detail.r7.prompt.compare.current')} />
        <Side side={view.other} name={t('detail.r7.prompt.compare.other')} />
      </div>
    </>
  );
}

function Side({ side, name }: { readonly side: BundleSide; readonly name: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  return (
    <section className={styles.group} aria-label={name}>
      <h3 className={styles.title}>{name}</h3>
      <p className={styles.aside}>
        {t('detail.r7.prompt.compare.bundle')}{' '}
        <code className={styles.original} data-original>
          {side.bundle.version ?? '-'} · {side.runId}
        </code>
        {side.systemPromptLines !== null
          ? ` · ${t('detail.r7.prompt.compare.rules', { n: count(side.systemPromptLines, language) })}`
          : ''}
      </p>
      {side.userPrompt === null ? (
        <p className={styles.line}>{t('detail.r7.prompt.compare.noText')}</p>
      ) : (
        <pre className={styles.pre} data-original tabIndex={0}>
          {side.userPrompt}
        </pre>
      )}
    </section>
  );
}
