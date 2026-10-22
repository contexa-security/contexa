import { useTranslation } from 'react-i18next';
import { DIFFERENCES } from '../../journey/journey';
import { useJourneyPlace } from '../../journey/useJourneyPlace';
import type { CardCopy } from '../../journey/copy';
import { SourceMark } from '../common/SourceMark';
import { DifferenceMark } from './JourneyParts';
import { RouteScreen } from './RouteScreen';
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

interface PartWrapProps {
  /** The sentence from the visitor's own run (work 18); null when there is no run of the part's case at all. */
  readonly sentence: string | null;
  /** The sentence comes from a run of the measurement because the visitor skipped the experience (D-37). */
  readonly measured: boolean;
  readonly differences: readonly number[];
}

/**
 * The wrap-up screen of a part (화면재편-기획안 T8, 8절): "what you saw so far", one sentence from the visitor's own run
 * under the part's guide line, and the six differences, the seen ones filled and the rest as the
 * questions still open. It takes over the act-end card, its "just seen" lines and its teaser; the frame adds the place,
 * the source line and the one main button to the next part.
 */
export function PartWrap({ sentence, measured, differences }: PartWrapProps) {
  const { t } = useTranslation();
  const place = useJourneyPlace();
  const number = place.screen?.number ?? '';
  const seen = new Set(differences);
  return (
    <RouteScreen
      title={t(`screen.${number}.title`)}
      purpose={t(`screen.${number}.guide`)}
      sourceLine={sentence ? t(measured ? 'frame.source.measured' : 'frame.source.run') : null}
    >
      {sentence ? <p className={styles.wrapSentence}>{sentence}</p> : null}
      <ol className={styles.six} data-count="exempt">
        {DIFFERENCES.map((difference) => (
          <li key={difference} className={styles.sixCell} data-seen={seen.has(difference) || undefined}>
            <DifferenceMark difference={difference} seen={seen.has(difference)} />
            <span>
              {seen.has(difference) ? t(`difference.${difference}`) : t(`difference.question.${difference}`)}
            </span>
          </li>
        ))}
      </ol>
    </RouteScreen>
  );
}
