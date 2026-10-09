import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ACT_MINUTES, DIFFERENCES, type Act } from '../../journey/journey';
import type { CardCopy } from '../../journey/copy';
import { ActionChip } from '../common/ActionChip';
import { SourceMark } from '../common/SourceMark';
import { DifferenceMark } from './JourneyParts';
import { ActionBar, MoreRow, NextLink } from './StepParts';
import styles from './Cards.module.css';

interface TeaserBandProps {
  readonly copy: CardCopy;
  /** What the band is: "next question" by default, the next act's name and minutes on an act-end screen. */
  readonly label?: string;
}

/**
 * The teaser (curiosity, 0-3), drawn right over the main action of the action area: one question and one measured
 * number, the answer hidden; the main button under it ("see next") answers it. The number carries the "measured" tag
 * (plan 1절 7).
 */
export function TeaserBand({ copy, label }: TeaserBandProps) {
  const { t } = useTranslation();
  const source = copy.teaserItem?.source ?? null;
  return (
    <div className={styles.teaser} data-teaser>
      <span className={styles.teaserLabel}>{label ?? t('teaser.label')}</span>
      <span className={styles.teaserQuestion}>{copy.question}</span>
      {/* The number keeps its line before the measurement arrives, so nothing moves. */}
      <span className={styles.teaserNumberLine}>
        <span className={styles.teaserNumber}>{copy.teaser ?? '\u00a0'}</span>
        {source ? (
          <SourceMark
            kind={
              source.kind === 'CASE_DEFINITION' ? 'CASE' : source.kind === 'RUN' ? 'ENGINE' : 'MEASUREMENT'
            }
            runId={source.kind === 'RUN' ? source.ref : null}
            measured
          >
            {source.kind === 'RUN' ? null : source.ref}
          </SourceMark>
        ) : null}
      </span>
    </div>
  );
}

interface ActEndCardProps {
  readonly act: Exclude<Act, 4>;
  readonly differences: readonly number[];
  /** The sentence from the visitor's own run (work 18); null when there is no run of the act's case at all. */
  readonly sentence: string | null;
  /** The sentence comes from a run of the measurement because the visitor skipped the experience (D-37). */
  readonly measured: boolean;
  readonly runId: string | null;
  /** The next act's teaser (question and measured number). */
  readonly next: CardCopy;
  readonly continueTo: string;
  /** The screen before, as the action area's way back. */
  readonly back: { readonly to: string; readonly label: string };
  readonly resendAsyncTo?: string | null;
  readonly benchmarkTo: string;
  /** The address to copy for "copy a link to this point". */
  readonly shareUrl: string;
}

/**
 * The act-end screen (act-end, D-41) in the screen grammar every screen follows: the card is the content (one
 * sentence from the visitor's own run and the six differences, the unseen ones as questions), the chips under it open
 * more, and the action area carries the next act's teaser over its one main button.
 */
export function ActEndCard({
  act,
  differences,
  sentence,
  measured,
  runId,
  next,
  continueTo,
  back,
  resendAsyncTo = null,
  benchmarkTo,
  shareUrl,
}: ActEndCardProps) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const seen = new Set(differences);
  const nextAct = (act + 1) as Act;
  return (
    <>
      <section className={styles.actEnd} aria-labelledby={`act-end-${act}`}>
        <header className={styles.actEndHead}>
          <h1 id={`act-end-${act}`} className={styles.actEndTitle}>
            {t('actEnd.title', { n: act, minutes: ACT_MINUTES[act] })}
          </h1>
        </header>
        {sentence ? (
          <p className={styles.sentence}>
            {sentence}
            <SourceMark kind="ENGINE" runId={runId} measured={measured}>
              {measured ? t('actEnd.measured') : null}
            </SourceMark>
          </p>
        ) : null}
        <ol className={styles.six}>
          {DIFFERENCES.map((difference) => (
            <li key={difference} className={styles.sixCell} data-seen={seen.has(difference) || undefined}>
              <DifferenceMark difference={difference} seen={seen.has(difference)} />
              <span>
                {seen.has(difference)
                  ? t(`difference.${difference}`)
                  : t(`difference.question.${difference}`)}
              </span>
            </li>
          ))}
        </ol>
      </section>
      <MoreRow>
        {resendAsyncTo ? (
          <ActionChip to={resendAsyncTo} icon="refresh" variant="open">
            {t('actEnd.resendAsync')}
          </ActionChip>
        ) : null}
        <ActionChip
          variant="open"
          icon={copied ? 'check' : 'link'}
          onClick={() => {
            void navigator.clipboard?.writeText(shareUrl).then(() => setCopied(true));
          }}
        >
          {copied ? t('actEnd.copied') : t('actEnd.copyLink')}
        </ActionChip>
        <ActionChip to={benchmarkTo} icon="chart" variant="open">
          {t('actEnd.benchmark')}
        </ActionChip>
      </MoreRow>
      <ActionBar
        back={back}
        teaser={
          <TeaserBand
            copy={next}
            label={t('actEnd.nextAct', { n: nextAct, minutes: ACT_MINUTES[nextAct] })}
          />
        }
        main={<NextLink to={continueTo} label={t('actEnd.start', { n: nextAct })} />}
        skip={false}
      />
    </>
  );
}
