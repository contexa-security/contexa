import type { ReasonCode } from '../../api/types';

/**
 * The dictionary key of a reason code's meaning. The output contract v4 (a v21 decision) has meanings of its own: its
 * judgment codes say what the model judged, where codes of the same name in the contract v3 stated facts the core had
 * computed (SC-6, 변경 6 of docs/showcase/프롬프트-v21-구현계획.md).
 */
export function reasonCodeKey(reason: Pick<ReasonCode, 'code' | 'contract'>): string {
  return `${reason.contract === 'V4' ? 'reasonCodeV4' : 'reasonCode'}.${reason.code}`;
}

/** The contract of a decision's reason codes: all codes of one decision come from one contract. */
export function contractOf(reasonCodes: readonly ReasonCode[]): string | null {
  return reasonCodes.find((reason) => reason.contract)?.contract ?? null;
}
