import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { InspectionCheck, RunFacts } from '../../api/promptQuality';
import type { ReasonCode } from '../../api/types';
import type { Verdict } from '../../domain/verdict';
import { Icon } from '../Icon';
import { VerdictChip } from '../VerdictChip';
import { FactCard } from './FactCard';
import { citedFact } from './factWords';
import styles from './Facts.module.css';

interface ReasonChainProps {
  /** The sealed decision's reason codes, each with the fact ID it cites (the quality view). */
  readonly reasonCodes: readonly ReasonCode[];
  /** The facts the AI received; null when the step's facts cannot be read. */
  readonly facts: RunFacts | null;
  readonly verdict: Verdict;
  readonly unresolved?: boolean;
  /** The official inspector's reason check of this decision, when it ran. */
  readonly check?: InspectionCheck | null;
}

/**
 * Why this decision (U-3): three columns joined by lines, the facts the AI received, the rules and reason codes they
 * led to, and the decision. Each reason code sits on the row of the fact it cites; pressing it marks that fact's
 * card. A reason that cites no fact, or a fact ID the AI did not receive, says "no link" in the fact's place (C-21).
 * The code's plain words are the fixed meaning of the output contract; the code itself is the original.
 */
export function ReasonChain({ reasonCodes, facts, verdict, unresolved = false, check = null }: ReasonChainProps) {
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
                <span>{t(`reasonCode.${reason.code}`, { defaultValue: t('reasonChain.otherCode') })}</span>
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
