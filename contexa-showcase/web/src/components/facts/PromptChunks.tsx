import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { FactBlock, PromptFact, RunFacts, RunQuality } from '../../api/promptQuality';
import { Icon } from '../Icon';
import { FactCard } from './FactCard';
import { blockOfLine, CHUNKS, factAnchor, factsOf, FOLDS, ribbonLines, sourcesOf, type RibbonItem } from './factWords';
import { QualityRibbon } from './QualityRibbon';
import { SourceChip } from './SourceChip';
import styles from './Facts.module.css';

interface PromptChunksProps {
  readonly facts: RunFacts;
  readonly quality: RunQuality | null;
}

/**
 * The AI input as the AI reads it (U-2): the quality ribbon, then the five parts in reading order (this request, this
 * session, usual behaviour, decision facts, unknown) with their source chips, and the past records and the outside
 * text folded under them. A part opens its fact cards below itself, not in a window; a failing ribbon item opens the
 * part of its fact and marks the card. Every fact is the server's line of the sealed prompt.
 */
export function PromptChunks({ facts, quality }: PromptChunksProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<FactBlock | null>('DECISION_FACTS');
  const [folds, setFolds] = useState<readonly FactBlock[]>([]);
  const [marked, setMarked] = useState<number | null>(null);
  const show = (_item: RibbonItem, line: number | null) => {
    const block = line === null ? null : blockOfLine(facts, line);
    if (line === null || block === null) {
      return;
    }
    if (CHUNKS.includes(block)) {
      setOpen(block);
    } else if (!folds.includes(block)) {
      setFolds([...folds, block]);
    }
    setMarked(line);
  };
  const cards = (block: FactBlock, list: readonly PromptFact[]) =>
    list.map((fact) => (
      <li key={fact.line}>
        <FactCard fact={fact} block={block} anchor={factAnchor(fact.line)} highlighted={marked === fact.line} />
      </li>
    ));
  const shownFolds = FOLDS.filter((block) => block !== 'SECOND_PASS' || factsOf(facts, block).length > 0);
  return (
    <div className={styles.chunks}>
      {quality?.ribbon ? (
        <QualityRibbon ribbon={quality.ribbon} lines={ribbonLines(quality, facts)} onShow={show} />
      ) : null}
      <ol className={styles.chunkList} aria-label={t('prompt.chunks')}>
        {CHUNKS.map((block, index) => {
          const list = factsOf(facts, block);
          const expanded = open === block;
          const panel = `prompt-chunk-${block}`;
          return (
            <li key={block} className={styles.chunk}>
              <button
                type="button"
                className={styles.chunkButton}
                aria-expanded={expanded}
                aria-controls={panel}
                onClick={() => setOpen(expanded ? null : block)}
              >
                {/* The reading order's place, a name rather than a value. */}
                <span className={styles.chunkNumber} aria-hidden="true">
                  {index + 1}
                </span>
                <span className={styles.chunkName}>{t(`prompt.block.${block}`)}</span>
                <span className={styles.chunkWhat}>{t(`prompt.blockWhat.${block}`)}</span>
                <span className={styles.chunkSources}>
                  {sourcesOf(list).map((source) => (
                    <SourceChip key={source ?? 'NONE'} source={source} />
                  ))}
                </span>
                <Icon name={expanded ? 'chevronDown' : 'chevronRight'} className={styles.chunkChevron} />
              </button>
              {expanded ? (
                list.length > 0 ? (
                  <ul id={panel} className={styles.chunkFacts} aria-label={t(`prompt.block.${block}`)}>
                    {cards(block, list)}
                  </ul>
                ) : (
                  <p id={panel} className={styles.empty}>
                    {t('prompt.noFacts')}
                  </p>
                )
              ) : null}
            </li>
          );
        })}
      </ol>
      <div className={styles.folds} role="group" aria-label={t('prompt.folds')}>
        {shownFolds.map((block) => {
          const list = factsOf(facts, block);
          return (
            <details
              key={block}
              className={styles.fold}
              open={folds.includes(block)}
              onToggle={(event) => {
                const now = event.currentTarget.open;
                if (now !== folds.includes(block)) {
                  setFolds(now ? [...folds, block] : folds.filter((entry) => entry !== block));
                }
              }}
            >
              <summary>
                {t(`prompt.block.${block}`)} · {t(`prompt.blockWhat.${block}`)}
              </summary>
              {list.length > 0 ? (
                <ul className={styles.foldFacts} aria-label={t(`prompt.block.${block}`)}>
                  {cards(block, list)}
                </ul>
              ) : (
                <p className={styles.empty}>{t('prompt.noFacts')}</p>
              )}
            </details>
          );
        })}
      </div>
    </div>
  );
}
