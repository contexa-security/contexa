import type { Verdict } from '../domain/verdict';
import type { UxIconName } from './ui/Icon';

/**
 * How the new screens draw a verdict (기획안 5.2 · 6.2 · 9절): one formal word, one icon and one of the five verdict
 * colours, the same everywhere. The engine's own code stays in src/domain/verdict.ts.
 */
export type VerdictTone = 'allow' | 'stepup' | 'hold' | 'block' | 'none';

export interface UxVerdict {
  readonly tone: VerdictTone;
  readonly icon: UxIconName;
  readonly labelKey: string;
}

export const UX_VERDICTS: Readonly<Record<Verdict, UxVerdict>> = {
  ALLOW: { tone: 'allow', icon: 'check', labelKey: 'ux.verdict.allow' },
  CHALLENGE: { tone: 'stepup', icon: 'key-round', labelKey: 'ux.verdict.stepup' },
  ESCALATE: { tone: 'hold', icon: 'pause', labelKey: 'ux.verdict.hold' },
  BLOCK: { tone: 'block', icon: 'ban', labelKey: 'ux.verdict.block' },
  PENDING: { tone: 'none', icon: 'hourglass', labelKey: 'ux.verdict.pending' },
  NONE: { tone: 'none', icon: 'minus', labelKey: 'ux.verdict.none' },
};

/** How a run's outcome is graded against the scenario's ground truth (평가 뱃지: no icon). */
export type EvalResult = 'correct' | 'normal' | 'partial' | 'missed' | 'falsePositive';

export const EVAL_TONES: Readonly<Record<EvalResult, VerdictTone>> = {
  correct: 'allow',
  normal: 'allow',
  partial: 'stepup',
  missed: 'block',
  falsePositive: 'block',
};
