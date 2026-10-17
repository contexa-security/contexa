import type { TFunction } from 'i18next';
import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { FactBlock, FactSufficiency, PromptFact } from '../../api/promptQuality';
import { factKey, factNoteKey, sourceOf } from './factWords';
import { SourceChip } from './SourceChip';
import styles from './Facts.module.css';

interface FactCardProps {
  readonly fact: PromptFact;
  readonly block: FactBlock;
  /** The card a pressed reason code or a failing ribbon item points to. */
  readonly highlighted?: boolean;
  /** The card's own address on the page, where one card stands for the line. */
  readonly anchor?: string | undefined;
}

/** The action sources the grey line names in plain words; any other source is named as another value. */
const NAMED_SOURCES: ReadonlySet<string> = new Set(['protectableMethod', 'httpMethod', 'method']);

/**
 * N-UI-1 (U1-5): the grey line under a card whose evidence is below strong: the grade, then each cause
 * the server read from the line and how many fields it marks for caution, in plain words. Every number
 * is the server's.
 */
function sufficiencyWords(t: TFunction, sufficiency: FactSufficiency): string {
  const causes = sufficiency.causes.map((cause) => {
    if (cause.kind !== 'ACTION_INFERRED') {
      return t(`fact.sufficiency.${cause.kind}`, { n: cause.count, of: cause.of });
    }
    const named = cause.from !== null && NAMED_SOURCES.has(cause.from) ? cause.from : 'other';
    const all = cause.count === cause.of;
    const key = all ? 'fact.sufficiency.ACTION_INFERRED_ALL' : 'fact.sufficiency.ACTION_INFERRED';
    return t(key, { n: cause.count, of: cause.of, from: t(`fact.sufficiency.from.${named}`) });
  });
  const cautions =
    sufficiency.cautions > 0 ? [t('fact.sufficiency.cautions', { n: sufficiency.cautions })] : [];
  const parts = [...causes, ...cautions];
  const grade = t(`fact.sufficiency.${sufficiency.grade}`);
  return parts.length > 0 ? `${grade}: ${parts.join(' · ')}` : grade;
}

/**
 * One fact the AI received (U-1, fact card): its fact ID, the plain words of its dictionary entry (and of its value
 * where W3-10 gave the line plain words), its source chip, and the "original" chip that opens, in place, the line as
 * it was sent, its line number and what the dictionary says the entry means. The line itself is the record's own
 * text, marked as the original. A user baseline line whose evidence the server reads as below strong
 * hangs a grey line under the card with the grade and its causes (N-UI-1, U1-5).
 */
export function FactCard({ fact, block, highlighted = false, anchor }: FactCardProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const boxId = useId();
  const card = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (highlighted) {
      card.current?.scrollIntoView({ block: 'nearest' });
    }
  }, [highlighted]);
  const key = factKey(fact.label);
  const note = factNoteKey(block, fact);
  return (
    <div
      ref={card}
      id={anchor}
      className={styles.factCard}
      data-highlight={highlighted || undefined}
      data-fact={fact.factId ?? undefined}
    >
      <div className={styles.factHead}>
        {fact.factId ? <span className={styles.factId}>{fact.factId}</span> : null}
        <span className={styles.factName}>{t(`fact.label.${key}`)}</span>
        <SourceChip source={fact.source} />
        <button
          type="button"
          className={styles.originalChip}
          aria-expanded={open}
          aria-controls={boxId}
          onClick={() => setOpen((value) => !value)}
        >
          {t('source.original')}
        </button>
      </div>
      {note ? <p className={styles.factNote}>{t(note)}</p> : null}
      {open ? (
        <div id={boxId} className={styles.factOriginal} role="group" aria-label={t('source.original')}>
          <code className={styles.factLine} data-original>
            {`${fact.label}: ${fact.value}`}
          </code>
          <span className={styles.factMeta}>{t('fact.lineNo', { n: fact.line })}</span>
          <span className={styles.factMeaning}>
            {t('fact.meaning')} · {t(`fact.meaning.${key}`)}
          </span>
          {fact.grades.length > 0 ? (
            <span className={styles.factGrades}>
              {t('fact.grades')}
              {fact.grades.map((grade) => (
                <SourceChip key={grade} source={sourceOf(grade)} />
              ))}
            </span>
          ) : null}
        </div>
      ) : null}
      {fact.sufficiency ? (
        <p className={styles.factSufficiency} data-sufficiency={fact.sufficiency.grade}>
          {sufficiencyWords(t, fact.sufficiency)}
        </p>
      ) : null}
    </div>
  );
}
