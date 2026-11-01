import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { VERDICTS, type Verdict } from '../../domain/verdict';
import { EVAL_TONES, UX_VERDICTS, type EvalResult, type VerdictTone } from '../verdict';
import { Icon, type UxIconName } from './Icon';
import styles from './Badge.module.css';

/**
 * Badges are 22 high with a 12 icon and 12/600 words (기획안 5.2). The five verdict tones are for verdicts and
 * evaluations only; `flag` is the neutral baseline deviation, `line` a category, `brand` Contexa itself and `sel` a
 * chosen value.
 */
export type BadgeTone = VerdictTone | 'brand' | 'line' | 'flag' | 'sel';

interface BadgeProps {
  readonly tone: BadgeTone;
  readonly icon?: UxIconName;
  readonly children: ReactNode;
  readonly className?: string;
}

export function Badge({ tone, icon, children, className }: BadgeProps) {
  return (
    <span className={[styles.badge, className].filter(Boolean).join(' ')} data-tone={tone}>
      {icon ? <Icon name={icon} size="xs" className={styles.icon} /> : null}
      {children}
    </span>
  );
}

interface VerdictBadgeProps {
  readonly verdict: Verdict;
  /** The engine's standard code (ALLOW, CHALLENGE…) after the word. */
  readonly showCode?: boolean;
  /** A finished request the engine gave no decision for (sent as PENDING): drawn as "no decision", never as analysing. */
  readonly unresolved?: boolean;
}

/** Word, icon and colour together, so a verdict never depends on colour alone. */
export function VerdictBadge({ verdict, showCode = false, unresolved = false }: VerdictBadgeProps) {
  const { t } = useTranslation();
  const shown: Verdict = unresolved ? 'NONE' : verdict;
  const look = UX_VERDICTS[shown];
  return (
    <Badge tone={look.tone} icon={look.icon}>
      {t(look.labelKey)}
      {showCode ? <span className={styles.code}>{VERDICTS[shown].code}</span> : null}
    </Badge>
  );
}

/** A run graded against its scenario's ground truth: the tone without an icon (기획안 5.2 평가 뱃지). */
export function EvalBadge({ result }: { readonly result: EvalResult }) {
  const { t } = useTranslation();
  return <Badge tone={EVAL_TONES[result]}>{t(`ux.eval.${result}`)}</Badge>;
}

/** A value outside the subject's behavioural baseline: neutral, so it never reads as a verdict. */
export function FlagBadge({ children }: { readonly children?: ReactNode }) {
  const { t } = useTranslation();
  return (
    <Badge tone="flag" icon="triangle-alert">
      {children ?? t('ux.flag.deviation')}
    </Badge>
  );
}
