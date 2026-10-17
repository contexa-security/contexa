import { useTranslation } from 'react-i18next';
import type { BundleSide, OtherBundleView } from '../../api/promptQuality';
import { count } from '../../journey/format';
import { compareOffered } from './factWords';
import styles from './Facts.module.css';

/** One side: its source (bundle name, hash, how it was selected, the run) above the text it sent. */
function Side({ side, name }: { readonly side: BundleSide; readonly name: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  return (
    <section className={styles.compareSide} aria-label={name}>
      <h3 className={styles.verifyName}>{name}</h3>
      <dl className={styles.compareSource}>
        <dt>{t('prompt.compare.bundle')}</dt>
        <dd data-original>{side.bundle.version ?? '-'}</dd>
        <dt>{t('prompt.compare.hash')}</dt>
        <dd data-original>{(side.bundle.hash ?? '-').slice(0, 12)}</dd>
        <dt>{t('prompt.compare.selection')}</dt>
        <dd data-original>{side.bundle.selectionSource ?? '-'}</dd>
        <dt>{t('prompt.compare.run')}</dt>
        <dd data-original>{side.runId}</dd>
      </dl>
      {side.systemPromptLines !== null ? (
        <p className={styles.factMeta}>
          {t('prompt.compare.systemLines', { n: count(side.systemPromptLines, language) })}
        </p>
      ) : null}
      {side.userPrompt === null ? (
        <p className={styles.empty}>{t('prompt.compare.noText')}</p>
      ) : (
        <pre className={styles.compareText} data-original tabIndex={0}>
          {side.userPrompt}
        </pre>
      )}
    </section>
  );
}

/**
 * The same case under the other bundle (U-2): not the same request, but the measured run of the same case and
 * conditions under the other prompt bundle, side by side with this run. Each side names its bundle, hash, selection
 * source and run as its source; the texts are the user prompts as sent. Shown only when the server found such a run.
 */
export function PromptCompare({ view }: { readonly view: OtherBundleView }) {
  const { t } = useTranslation();
  if (!compareOffered(view) || view.current === null || view.other === null) {
    return null;
  }
  return (
    <div className={styles.verify}>
      <p className={styles.verifyLine}>{t('prompt.compare.lead')}</p>
      <div className={styles.compare}>
        <Side side={view.current} name={t('prompt.compare.current')} />
        <Side side={view.other} name={t('prompt.compare.other')} />
      </div>
    </div>
  );
}

/**
 * N-UI-1 (U2-6): the same case's user prompt length under the earlier and the later bundle, as the server
 * named, counted and ordered them; nothing while the server has no such pair.
 */
export function SameCaseLines({ view }: { readonly view: OtherBundleView | null }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const lines = compareOffered(view) ? (view?.lines ?? null) : null;
  if (lines === null) {
    return null;
  }
  return (
    <p className={styles.sameCaseLines} data-lines>
      {t('prompt.compare.lines', {
        before: lines.before,
        beforeLines: count(lines.beforeLines, language),
        after: lines.after,
        afterLines: count(lines.afterLines, language),
      })}
    </p>
  );
}
