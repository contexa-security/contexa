import type { TFunction } from 'i18next';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { InspectionCheck, RunFacts } from '../../api/promptQuality';
import type { ReasonCode } from '../../api/types';
import type { Verdict } from '../../domain/verdict';
import { Icon } from '../Icon';
import { VerdictChip } from '../VerdictChip';
import { FactCard } from './FactCard';
import { citedFact, factKey } from './factWords';
import { contractOf, reasonCodeKey } from './reasonMeaning';
import styles from './Facts.module.css';
import plain from './ReasonChain.module.css';

/** The fact that changed from the try before, marked on the reason screen (2-4: the company approval). */
export interface ChangedFact {
  /** The fact ID of the changed line among the facts the AI received; null when the facts cannot be read. */
  readonly fact: string | null;
  readonly tag: ReactNode;
  /** Its words when no reason cites it; null for none. */
  readonly words?: string | null;
}

interface ReasonChainProps {
  /** The sealed decision's reason codes, each with the fact ID it cites (the quality view). */
  readonly reasonCodes: readonly ReasonCode[];
  /** The facts the AI received; null when the step's facts cannot be read. */
  readonly facts: RunFacts | null;
  readonly verdict: Verdict;
  readonly unresolved?: boolean;
  /** The official inspector's reason check of this decision, when it ran. */
  readonly check?: InspectionCheck | null;
  /**
   * 'chain' (the default): the full chain with every reason code, its fact card and the inspector's check, for the
   * places that show the record. 'plain': the reason screen's figure (화면재편 T6), each cited fact once in plain words.
   */
  readonly mode?: 'chain' | 'plain';
  /** Plain mode only: the fact that changed from the try before, first and tagged. */
  readonly changed?: ChangedFact | null;
}

/**
 * Why this decision (U-3): three columns joined by lines, the facts the AI received, the rules and reason codes they
 * led to, and the decision. Each reason code sits on the row of the fact it cites; pressing it marks that fact's
 * card. A reason that cites no fact, or a fact ID the AI did not receive, says "no link" in the fact's place (C-21).
 * The code's plain words are the fixed meaning of the output contract; the code itself is the original.
 * In its plain mode it draws the reason screen's figure instead (F-1).
 */
export function ReasonChain({
  reasonCodes,
  facts,
  verdict,
  unresolved = false,
  check = null,
  mode = 'chain',
  changed = null,
}: ReasonChainProps) {
  if (mode === 'plain') {
    return (
      <PlainChain
        reasonCodes={reasonCodes}
        facts={facts}
        verdict={verdict}
        unresolved={unresolved}
        changed={changed}
      />
    );
  }
  return (
    <FullChain reasonCodes={reasonCodes} facts={facts} verdict={verdict} unresolved={unresolved} check={check} />
  );
}

function FullChain({
  reasonCodes,
  facts,
  verdict,
  unresolved,
  check,
}: Required<Pick<ReasonChainProps, 'reasonCodes' | 'facts' | 'verdict' | 'unresolved' | 'check'>>) {
  const { t } = useTranslation();
  const [picked, setPicked] = useState<string | null>(null);
  const readable = facts?.available === true;
  return (
    <div className={styles.chain} role="group" aria-label={t('reasonChain.title')}>
      <div className={styles.chainHead} aria-hidden="true">
        <span>{t('reasonChain.facts')}</span>
        <span />
        <span>{t('reasonChain.codes')}</span>
      </div>
      <ol className={styles.chainRows}>
        {reasonCodes.map((reason, index) => {
          const cited = citedFact(facts, reason.fact);
          const rowKey = `${reason.code}-${reason.fact ?? ''}-${index}`;
          return (
            <li key={rowKey} className={styles.chainRow} data-linked={cited !== null || undefined}>
              {cited ? (
                <FactCard
                  fact={cited.fact}
                  block={cited.block}
                  highlighted={picked !== null && picked === reason.fact}
                />
              ) : reason.fact !== null && !readable ? (
                <span className={styles.factOnly}>
                  <span className={styles.factId}>{reason.fact}</span>
                  {t('reasonChain.noCard')}
                </span>
              ) : (
                <span className={styles.noLink}>{t('reasonChain.noLink')}</span>
              )}
              <span className={styles.chainLine} aria-hidden="true" />
              <button
                type="button"
                className={styles.codeButton}
                aria-pressed={picked !== null && picked === reason.fact && cited !== null}
                onClick={() => setPicked(cited ? reason.fact : null)}
              >
                <span>{t(reasonCodeKey(reason), { defaultValue: t('reasonChain.otherCode') })}</span>
                <code className={styles.codeName} data-original>
                  {reason.fact ? `${reason.code} · ${reason.fact}` : reason.code}
                </code>
              </button>
            </li>
          );
        })}
      </ol>
      <div className={styles.chainDecision}>
        <span className={styles.chainLabel}>{t('reasonChain.decision')}</span>
        <VerdictChip verdict={verdict} unresolved={unresolved} size="lg" />
      </div>
      {check ? (
        <p className={styles.check} data-ok={check.mismatched === 0}>
          <Icon name={check.mismatched === 0 ? 'check' : 'cross'} />
          {t('reasonChain.check', {
            matched: check.matched,
            mismatched: check.mismatched,
            unverifiable: check.unverifiable,
          })}
        </p>
      ) : null}
    </div>
  );
}

/** One card of the reason figure: a fact's plain name (or the changed tag) and the plain words of its reasons. */
export interface ReasonItem {
  readonly key: string;
  /** The fact the card stands for, as a data mark only; fact IDs are never shown (RC-2). */
  readonly fact?: string | null;
  readonly tag?: ReactNode;
  readonly name?: ReactNode;
  readonly words: readonly string[];
}

/** The reason screen shows three cards at most (T6); the rest is in the decision details. */
const PLAIN_CARDS = 3;

/**
 * The cited facts in plain words, each fact once (F-1): the reasons are grouped by the fact they cite, in the order
 * the server gave them, the reasons citing no fact the AI received after them. Only names and IDs are matched here.
 */
function plainItems(
  t: TFunction,
  reasonCodes: readonly ReasonCode[],
  facts: RunFacts | null,
  changed: ChangedFact | null = null,
): readonly ReasonItem[] {
  const readable = facts?.available === true;
  const linked = new Map<string, { name: string | null; codes: string[] }>();
  const unlinked: string[] = [];
  for (const reason of reasonCodes) {
    const cited = citedFact(facts, reason.fact);
    // With unreadable facts the cited ID still tells which reasons belong together; it is never shown.
    const id = cited ? reason.fact : !readable ? reason.fact : null;
    const codes = id === null ? unlinked : (linked.get(id)?.codes ?? []);
    if (!codes.includes(reason.code)) {
      codes.push(reason.code);
    }
    if (id !== null && !linked.has(id)) {
      linked.set(id, { name: cited ? t(`fact.label.${factKey(cited.fact.label)}`) : null, codes });
    }
  }
  const contract = contractOf(reasonCodes);
  const meaning = (code: string) =>
    t(reasonCodeKey({ code, contract }), { defaultValue: t('p1.reason.otherCode') });
  const items: ReasonItem[] = [...linked].map(([id, group]) => ({
    key: id,
    fact: id,
    name: group.name,
    words: group.codes.map(meaning),
  }));
  if (unlinked.length > 0) {
    // "Other reasons" only next to fact cards; alone the reasons need no heading.
    const name = items.length > 0 ? t('p1.reason.unlinked') : null;
    items.push({ key: '', fact: null, name, words: unlinked.map(meaning) });
  }
  if (!changed) {
    return items;
  }
  const at = changed.fact === null ? -1 : items.findIndex((item) => item.fact === changed.fact);
  const found = at >= 0 ? items.splice(at, 1)[0] : undefined;
  const tagged: ReasonItem = found
    ? { ...found, tag: changed.tag }
    : {
        key: `changed-${changed.fact ?? ''}`,
        fact: changed.fact,
        tag: changed.tag,
        words: changed.words ? [changed.words] : [],
      };
  return [tagged, ...items];
}

function PlainChain({
  reasonCodes,
  facts,
  verdict,
  unresolved,
  changed,
}: Required<Pick<ReasonChainProps, 'reasonCodes' | 'facts' | 'verdict' | 'unresolved' | 'changed'>>) {
  const { t } = useTranslation();
  return (
    <ReasonFigure
      items={plainItems(t, reasonCodes, facts, changed)}
      verdict={verdict}
      unresolved={unresolved}
    />
  );
}

interface ReasonFigureProps {
  readonly items: readonly ReasonItem[];
  readonly verdict: Verdict;
  readonly unresolved?: boolean;
}

/**
 * The reason screen's one figure (T6): the cited facts as plain cards, an arrow, and the judgment they led to. No
 * code, fact ID or source chip is drawn; those stay in the decision details. Past three cards one quiet line says the
 * others are there.
 */
export function ReasonFigure({ items, verdict, unresolved = false }: ReasonFigureProps) {
  const { t } = useTranslation();
  const shown = items.slice(0, PLAIN_CARDS);
  return (
    <>
      <div className={plain.figure} role="group" aria-label={t('p1.reason.figure')}>
        <ul className={plain.facts}>
          {shown.map((item) => (
            <li
              key={item.key}
              className={plain.fact}
              data-fact={item.fact ?? undefined}
              data-changed={item.tag ? true : undefined}
            >
              {item.tag ? (
                <p className={plain.tag}>{item.tag}</p>
              ) : item.name ? (
                <p className={plain.name}>{item.name}</p>
              ) : null}
              {item.words.length > 0 ? <p className={plain.words}>{item.words.join(' ')}</p> : null}
            </li>
          ))}
        </ul>
        <Icon name="arrowRight" className={plain.arrow} />
        <span className={plain.verdict}>
          <VerdictChip verdict={verdict} unresolved={unresolved} size="lg" />
        </span>
      </div>
      {items.length > PLAIN_CARDS ? <p className={plain.more}>{t('p1.reason.more')}</p> : null}
    </>
  );
}
