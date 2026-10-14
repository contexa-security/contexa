import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { DecisionAnatomyView, ExchangeCall } from '../../api/anatomy';
import { count } from '../../journey/format';
import styles from '../../pages/try/PromptPage.module.css';
import { plainLinesOf, sectionsOf, shownBundles, trimEnd, type Block, type Bundle } from './promptSections';

interface PromptBundlesProps {
  readonly lines: NonNullable<DecisionAnatomyView['promptLines']>;
  readonly call: ExchangeCall;
}

/**
 * The prompt as its bundles with the server's line counts, and for the bundle pressed its original lines next to
 * plain words (e1-prompt; the decision details' prompt tab shows the same). A v20 prompt shows one bundle per block
 * (W3-10).
 */
export function PromptBundles({ lines, call }: PromptBundlesProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const v20 = lines.layout === 'V20_BLOCKS';
  const bundles = shownBundles(lines);
  const [picked, setPicked] = useState<Bundle | Block>(v20 ? 'DECISION_FACTS' : 'COMPANY');
  const name = (bundle: Bundle | Block): string => t(v20 ? `prompt.block.${bundle}` : `prompt.bundle.${bundle}`);
  const what = (bundle: Bundle | Block): string =>
    t(v20 ? `prompt.blockWhat.${bundle}` : `prompt.bundleWhat.${bundle}`);
  const sections = sectionsOf(call.userPrompt);
  const bundleLines = (bundle: Bundle | Block): readonly string[] =>
    bundle === 'RULES'
      ? (call.systemPrompt ?? '').split('\n')
      : lines.sections
          .filter((section) => section.bundle === bundle)
          .flatMap((section) => sections.get(section.name) ?? []);
  // A section's trailing blank lines are not lines of text; dropping them keeps the shown count the server's count.
  const original = trimEnd(bundleLines(picked));
  const plain = plainLinesOf(lines.layout, picked, original);
  return (
    <div className={styles.layout}>
      <ol className={styles.bundles} aria-label={t(v20 ? 'prompt.blocks' : 'prompt.bundles')}>
        {bundles.map((bundle) => (
          <li key={bundle}>
            <button
              type="button"
              className={styles.bundle}
              aria-pressed={picked === bundle}
              onClick={() => setPicked(bundle)}
            >
              <span className={styles.bundleName}>{name(bundle)}</span>
              <span className={styles.bundleWhat}>{what(bundle)}</span>
              <span className={styles.bundleLines}>
                {t('prompt.lines', {
                  n: count(lines.bundles.find((entry) => entry.bundle === bundle)?.lines ?? 0, language),
                })}
              </span>
            </button>
          </li>
        ))}
      </ol>
      <section className={styles.view} aria-labelledby="prompt-view">
        <h2 id="prompt-view" className={styles.viewTitle}>
          {name(picked)}
        </h2>
        {plain.length > 0 ? (
          <ul className={styles.plain} aria-label={t('prompt.plainTitle')}>
            {plain.map((entry) => (
              <li key={entry.line} className={styles.plainRow}>
                <code className={styles.plainOriginal} data-original>
                  {entry.line.trim()}
                </code>
                <span className={styles.plainWords}>{t(entry.key)}</span>
              </li>
            ))}
          </ul>
        ) : null}
        <div className={styles.originalLabel}>{t('prompt.originalLabel', { n: original.length })}</div>
        {/* A box that scrolls inside is reached by the keyboard too (axe scrollable-region-focusable). */}
        <ol
          className={styles.original}
          data-original
          tabIndex={0}
          aria-label={t('prompt.originalLabel', { n: original.length })}
        >
          {original.map((line, index) => (
            // The original's own line order is the identity of a line.
            <li key={index} className={styles.originalLine}>
              {line}
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
