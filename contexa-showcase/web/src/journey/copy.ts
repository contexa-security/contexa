import type { TFunction } from 'i18next';
import type { ActEnd } from '../api/journey';
import type { Teaser, TeaserKey, TeasersView } from '../api/teasers';
import { count, seconds } from './format';

/**
 * Picks the wording of the teaser cards and the act-end cards from the values the server gave (work 18, 19). The
 * sentence frames are the design's (0-3 table, act-end slide); a sentence that states a fact is used only when the
 * server says the record makes it true (`holds`), otherwise the approved fallback (plan 8절). Nothing is computed here:
 * numbers are only formatted.
 */
export type CardKey = TeaserKey | 'G_LEARNED_FLOW' | 'DILEMMA_DIFFERENCES';

export interface CardCopy {
  readonly question: string;
  /** The measured teaser; null when the source has no value yet (the card then shows the question only). */
  readonly teaser: string | null;
  readonly teaserItem: Teaser | null;
}

function number(value: unknown): number | null {
  return typeof value === 'number' ? value : null;
}

export function teaserCopy(
  t: TFunction,
  language: string,
  key: CardKey,
  teasers: TeasersView | undefined,
  differencesSeen: number,
): CardCopy {
  const base = `teaser.${key}`;
  if (key === 'G_LEARNED_FLOW') {
    return { question: t(`${base}.question`), teaser: t(`${base}.teaser`), teaserItem: null };
  }
  if (key === 'DILEMMA_DIFFERENCES') {
    return {
      question: t(`${base}.question`),
      teaser: t(`${base}.teaser`, { n: differencesSeen }),
      teaserItem: null,
    };
  }
  const item = teasers?.teasers.find((candidate) => candidate.key === key) ?? null;
  const values = item?.values ?? {};
  const fallback = item?.holds === false;
  const ask = (params?: Record<string, string>) => t(`${base}.question`, params ?? {});
  if (!item || item.missing) {
    return { question: questionWithoutValues(t, key, base), teaser: null, teaserItem: item };
  }
  switch (key) {
    case 'HOOK_TRY':
      return copy(ask(), t(`${base}.teaser`, { items: formatted(values['items'], language) }), item);
    case 'E1_RESULT_FACTS':
      return copy(
        ask(),
        fallback ? t(`${base}.fallback`) : t(`${base}.teaser`, { count: values['count'] }),
        item,
      );
    case 'E1_REASON_MAILBOX':
    case 'E2_RESULT_DIFF':
      return copy(ask(), t(fallback ? `${base}.fallback` : `${base}.teaser`), item);
    case 'E1_AFTER_RULES':
      return copy(
        ask(),
        fallback
          ? t(`${base}.fallback`, { runs: values['runs'], refused: values['refused'] })
          : t(`${base}.teaser`),
        item,
      );
    case 'G_RULES_RESUME': {
      const ms = number(values['reissueMs']);
      return copy(
        ask(),
        fallback || ms === null ? t(`${base}.fallback`) : t(`${base}.teaser`, { seconds: seconds(ms) }),
        item,
      );
    }
    case 'FOLLOW_LEARNED':
      return copy(ask(), t(`${base}.teaser`, { learned: formatted(values['learned'], language) }), item);
    case 'LEARN_WHY_TAUGHT':
      return copy(
        ask(),
        t(`${base}.teaser`, {
          reads: values['reads'],
          downloads: values['downloads'],
          exports: values['exports'],
        }),
        item,
      );
    case 'G_HOW_LINES':
      return copy(ask(), t(`${base}.teaser`, { lines: formatted(values['lines'], language) }), item);
    case 'E1_PROMPT_ASYNC': {
      const ms = number(values['analysisMs']);
      const delivered = Array.isArray(values['delivered']) ? (values['delivered'] as unknown[]) : [];
      return copy(
        ask({ seconds: ms === null ? '-' : seconds(ms) }),
        fallback || delivered.length === 0
          ? t(`${base}.fallback`)
          : t(`${base}.teaser`, { items: formatted(delivered[0], language) }),
        item,
      );
    }
    case 'SYNC_WHEN_OBSERVATIONS':
      return copy(ask(), t(`${base}.teaser`, { from: values['from'], to: values['to'] }), item);
    case 'LEARN_AFTER_FALSE_BLOCKS':
      return copy(
        ask(),
        fallback
          ? t(`${base}.fallback`)
          : t(`${base}.teaser`, { numberRule: values['numberRule'], contexa: values['contexa'] }),
        item,
      );
    case 'G_WHERE_C2':
      return copy(
        ask(),
        fallback ? t(`${base}.fallback`) : t(`${base}.teaser`, { stopped: values['stopped'] }),
        item,
      );
    default:
      return { question: ask(), teaser: null, teaserItem: item };
  }
}

/** A question that itself carries a measured value cannot be asked without it; the others are asked as written. */
function questionWithoutValues(t: TFunction, key: CardKey, base: string): string {
  return key === 'E1_PROMPT_ASYNC' ? t('teaser.see') : t(`${base}.question`);
}

function copy(question: string, teaser: string, item: Teaser): CardCopy {
  return { question, teaser, teaserItem: item };
}

function formatted(value: unknown, language: string): string {
  return typeof value === 'number' ? count(value, language) : String(value ?? '-');
}

/**
 * The act-end sentence from the visitor's own run (work 18): the server gives the codes (Contexa's result and action,
 * the number rule's result) and the numbers; the code picks the sentence frame.
 */
export function actEndSentence(t: TFunction, language: string, card: ActEnd): string {
  const values = card.values;
  if (card.act === 1) {
    const result = values['result'];
    const action = values['engineAction'];
    const params = {
      requested: formatted(values['requested'], language),
      delivered: formatted(values['delivered'], language),
      seconds: typeof values['analysisMs'] === 'number' ? seconds(values['analysisMs']) : '-',
    };
    if (result === 'STOPPED') {
      const known = action === 'CHALLENGE' || action === 'BLOCK' || action === 'ESCALATE';
      return t(known ? `actEnd.1.STOPPED.${String(action)}` : 'actEnd.1.STOPPED.other', params);
    }
    if (result === 'PARTLY_STOPPED' || result === 'MISSED') {
      return t(`actEnd.1.${result}`, params);
    }
    return t('actEnd.1.other', params);
  }
  if (card.act === 2) {
    const result = values['result'];
    if (result === 'PASSED' || result === 'PASSED_AFTER_CHECK') {
      return t(values['numberRule'] === 'HALTED' ? 'actEnd.2.passed' : 'actEnd.2.passedRulesToo');
    }
    return t(result === 'HALTED' ? 'actEnd.2.halted' : 'actEnd.2.other');
  }
  const from = number(values['from']);
  const to = number(values['to']);
  if (from === null || to === null) {
    return t('actEnd.3.other');
  }
  return t(to > from ? 'actEnd.3.grew' : 'actEnd.3.same', { from, to });
}
