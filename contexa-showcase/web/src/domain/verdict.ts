/**
 * Engine and control verdicts. Every place that shows a verdict uses the same word, icon and color
 * (design rule "same meaning, same shape"), so the presentation metadata lives here only.
 */
export type Verdict = 'ALLOW' | 'CHALLENGE' | 'ESCALATE' | 'BLOCK' | 'PENDING';

export type VerdictIcon = 'check' | 'key' | 'clock' | 'lock' | 'hourglass';

export interface VerdictPresentation {
  /** i18n key of the plain-language word shown to visitors. */
  readonly labelKey: string;
  /** Standard engine code shown as a small badge next to the plain word. */
  readonly code: string;
  readonly icon: VerdictIcon;
  /** CSS custom property holding the verdict color. */
  readonly colorVar: string;
}

export const VERDICTS: Readonly<Record<Verdict, VerdictPresentation>> = {
  ALLOW: { labelKey: 'verdict.allow', code: 'ALLOW', icon: 'check', colorVar: '--color-verdict-allow' },
  CHALLENGE: { labelKey: 'verdict.verify', code: 'CHALLENGE', icon: 'key', colorVar: '--color-verdict-verify' },
  ESCALATE: { labelKey: 'verdict.review', code: 'ESCALATE', icon: 'clock', colorVar: '--color-verdict-review' },
  BLOCK: { labelKey: 'verdict.block', code: 'BLOCK', icon: 'lock', colorVar: '--color-verdict-block' },
  PENDING: { labelKey: 'verdict.pending', code: 'PENDING_ANALYSIS', icon: 'hourglass', colorVar: '--color-verdict-pending' },
};

/**
 * Business outcome is the primary judgement criterion: was the data delivered, did the work finish. CUT is a stream the
 * engine stopped part-way; what left before the cut is shown with it (deck p.11).
 */
export type BusinessOutcome = 'DELIVERED' | 'STOPPED' | 'CUT' | 'HELD' | 'UNRESOLVED';

export const OUTCOME_KEYS: Readonly<Record<BusinessOutcome, string>> = {
  DELIVERED: 'outcome.delivered',
  STOPPED: 'outcome.stopped',
  CUT: 'outcome.cut',
  HELD: 'outcome.held',
  UNRESOLVED: 'outcome.unresolved',
};

/** The five controls in the order of the security layers they look at (deck page 7). */
export type ControlId = 'A' | 'B' | 'C1' | 'C2' | 'D';

export const CONTROL_ORDER: readonly ControlId[] = ['A', 'B', 'C1', 'C2', 'D'];
