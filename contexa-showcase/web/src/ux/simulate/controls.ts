import type { ControlId } from '../../domain/verdict';

/** The control's colour in comparisons (기획안 6.2 통제 5색): four steps of grey-blue, Contexa gold. */
export const CONTROL_TONE: Readonly<Record<ControlId, 'waf' | 'iam' | 'rule' | 'approval' | 'brand'>> = {
  A: 'waf',
  B: 'iam',
  C1: 'rule',
  C2: 'approval',
  D: 'brand',
};
