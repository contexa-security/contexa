import { useTranslation } from 'react-i18next';
import type { LiveLayer, LiveStream } from '../../../api/types';
import type { ControlId } from '../../../domain/verdict';
import { count, seconds } from '../../../journey/format';
import styles from '../Experience.module.css';
import { verdictKey } from './liveRun';
import ownStyles from './LiveRunBar.module.css';

/**
 * The words a screen gives its bars in place of the tries' own (the lab, T-01 and B-07): a refusal, a cut (each with
 * its seconds; the cut with the items out and the total when the export said it), and Contexa's line while its AI is
 * still judging a streamed export that keeps going out.
 */
export interface BarWords {
  readonly denied: string;
  readonly deniedOnly: string;
  readonly cutAtOf: string;
  readonly cutAt: string;
  readonly judgingStream: string;
  readonly judgingStreamNoTotal: string;
}

export interface BarProps {
  readonly control: ControlId;
  readonly layer: LiveLayer | null;
  readonly axis: number;
  /** Contexa held the response while deciding (synchronous). */
  readonly held: boolean;
  readonly verdict: string | null;
  /** The words for Contexa's answer while its judgment is still loading; the redesigned try passes its own. */
  readonly decidingKey?: string;
  /** Contexa's judgment may still come: its line names the judgment, not the files, until then. */
  readonly deciding?: boolean;
  /** The words of a line that has not answered yet, when the screen knows more than "waiting". */
  readonly waitingLabel?: string | undefined;
  /**
   * A run of several requests: the bar's length shows the time, so the words say the answer only (the number limit,
   * RC-1); a run of one request keeps its seconds, the try's point (Contexa judged in 8 s).
   */
  readonly answerOnly?: boolean;
  /** Contexa's line of a later request stopped by an earlier judgment (the stored step's timing PRIOR_DECISION). */
  readonly prior?: boolean;
  /**
   * The control's streamed export as the portal reads it (판정층 8절 9): the bar grows with the items that left, and a
   * block of Contexa that cut the stream names where it stopped.
   */
  readonly stream?: LiveStream | null;
  /** The screen's own words for a refusal, a cut and a stream under judgment; the tries' words when absent. */
  readonly words?: BarWords | null;
}

/**
 * The label a screen with its own words gives an answer (the lab, T-01 and B-07), or null where the tries' words
 * apply: a cut as the result chip "blocked after some left" with its seconds and what went out, Contexa's AI still
 * judging while the export keeps going out, and an existing approach's refusal as "blocked".
 */
function ownLabel(
  t: ReturnType<typeof useTranslation>['t'],
  language: string,
  words: BarWords,
  props: Pick<BarProps, 'control' | 'layer' | 'deciding' | 'answerOnly'> & {
    readonly stream: LiveStream | null;
  },
): string | null {
  const { control, layer, deciding, answerOnly, stream } = props;
  const total = stream?.total ?? null;
  const totalText = total === null ? '' : count(total, language);
  if (control === 'D' && layer?.outcome === 'CUT') {
    return t(total !== null ? words.cutAtOf : words.cutAt, {
      seconds: seconds(layer.elapsedMs),
      items: count(layer.deliveredItems, language),
      total: totalText,
    });
  }
  if (control === 'D' && deciding && !layer && stream) {
    return t(total !== null ? words.judgingStream : words.judgingStreamNoTotal, {
      seconds: seconds(stream.atMs),
      items: count(stream.delivered, language),
      total: totalText,
    });
  }
  if (control !== 'D' && layer && layer.outcome !== 'DELIVERED') {
    return answerOnly ? t(words.deniedOnly) : t(words.denied, { seconds: seconds(layer.elapsedMs) });
  }
  return null;
}

/** One approach's answer on the time axis, with its recorded time and what it let out. */
export function Bar({
  control,
  layer,
  axis,
  held,
  verdict,
  decidingKey = 'e1.run.decisionLoading',
  deciding = false,
  waitingLabel,
  answerOnly = false,
  prior = false,
  stream = null,
  words = null,
}: BarProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  // A finished answer is drawn on the time axis; a stream still read as far as its items got (the words say the same).
  const width = layer
    ? Math.max(2, Math.round((layer.elapsedMs / axis) * 100))
    : stream
      ? Math.max(
          2,
          Math.round(stream.total ? (stream.delivered / stream.total) * 100 : (stream.atMs / axis) * 100),
        )
      : 0;
  const total = stream?.total ?? null;
  const isCut = control === 'D' && layer?.outcome === 'CUT';
  const own = words ? ownLabel(t, language, words, { control, layer, deciding, answerOnly, stream }) : null;
  const cut = isCut
    ? total !== null
      ? t('p1.run.cutAtOf', { items: count(layer.deliveredItems, language), total: count(total, language) })
      : t('p1.run.cutAt', { items: count(layer.deliveredItems, language) })
    : null;
  const decided =
    control === 'D' && verdict && layer
      ? answerOnly
        ? t(verdictKey(verdict))
        : t('e1.run.decided', { seconds: seconds(layer.elapsedMs), verdict: t(verdictKey(verdict)) })
      : null;
  const label =
    own ??
    (cut
      ? decided
        ? `${decided} · ${cut}`
        : cut
      : !layer && stream
        ? total !== null
          ? t('p1.run.streamingOf', {
              items: count(stream.delivered, language),
              total: count(total, language),
            })
          : t('p1.run.streaming', { items: count(stream.delivered, language) })
        : !layer
          ? (waitingLabel ?? t('e1.run.waiting'))
          : control === 'D' && verdict
            ? answerOnly
              ? t(verdictKey(verdict))
              : t('e1.run.decided', {
                  seconds: seconds(layer.elapsedMs),
                  verdict: t(verdictKey(verdict)),
                })
            : control === 'D' && prior
              ? answerOnly
                ? t('p1.run.priorOnly')
                : t('p1.run.prior', { seconds: seconds(layer.elapsedMs) })
              : control === 'D' && deciding
                ? t(decidingKey, { seconds: seconds(layer.elapsedMs) })
                : layer.outcome === 'DELIVERED'
                  ? answerOnly
                    ? t('p1.run.outOnly', { items: count(layer.deliveredItems, language) })
                    : t('e1.run.out', {
                        seconds: seconds(layer.elapsedMs),
                        items: count(layer.deliveredItems, language),
                      })
                  : control === 'D'
                    ? // Contexa's answer is its decision; until the decision block arrives it is not called a denial.
                      t(decidingKey, { seconds: seconds(layer.elapsedMs) })
                    : answerOnly
                      ? t('p1.run.deniedOnly')
                      : t('e1.run.denied', { seconds: seconds(layer.elapsedMs) }));
  return (
    <li className={styles.bar} data-control={control} data-cut={isCut || undefined}>
      <span className={styles.barName}>{t(`control.${control}.name`)}</span>
      <span className={styles.barTrack}>
        <span
          className={styles.barFill}
          data-outcome={layer?.outcome ?? 'PENDING'}
          data-held={held || undefined}
          style={{ width: `${width}%` }}
        />
      </span>
      {/* The lab marks the moment Contexa cut the export, the moment its stream screen is about (B-07). */}
      <span className={words && isCut ? `${styles.barLabel} ${ownStyles.cut}` : styles.barLabel}>
        {label}
      </span>
    </li>
  );
}
