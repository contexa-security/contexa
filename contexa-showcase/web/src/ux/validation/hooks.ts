import { useTranslation } from 'react-i18next';
import { useDecisionQuality, type ControlScore } from '../../api/benchmark';
import { usePromptQuality } from '../../api/promptQuality';
import type { BarTone } from '../ui';

export interface ResultSegment {
  readonly key: string;
  readonly label: string;
  readonly value: number;
  readonly tone: BarTone;
}

/** The parts of a control's runs: the attacks by how they ended, the normal work by how it passed. */
export function useSegments() {
  const { t } = useTranslation();
  const attack = (score: ControlScore): ResultSegment[] => [
    { key: 'stopped', label: t('ux.validation.seg.stopped'), value: score.stopped.hits, tone: 'allow' },
    { key: 'partial', label: t('ux.validation.seg.partial'), value: score.partlyStopped, tone: 'stepup' },
    { key: 'missed', label: t('ux.validation.seg.missed'), value: score.missed, tone: 'block' },
    {
      key: 'unresolved',
      label: t('ux.validation.seg.unresolved'),
      value: score.attackUnresolved,
      tone: 'none',
    },
  ];
  const normal = (score: ControlScore): ResultSegment[] => [
    { key: 'passed', label: t('ux.validation.seg.passed'), value: score.normalPassed, tone: 'allow' },
    { key: 'checked', label: t('ux.validation.seg.checked'), value: score.friction.hits, tone: 'hold' },
    { key: 'blocked', label: t('ux.validation.seg.blocked'), value: score.falseBlock.hits, tone: 'block' },
    {
      key: 'unresolved',
      label: t('ux.validation.seg.unresolved'),
      value: score.normalUnresolved,
      tone: 'none',
    },
  ];
  const legend: readonly { readonly label: string; readonly tone: BarTone }[] = [
    { label: t('ux.validation.seg.stopped'), tone: 'allow' },
    { label: t('ux.validation.seg.passed'), tone: 'allow' },
    { label: t('ux.validation.seg.partial'), tone: 'stepup' },
    { label: t('ux.validation.seg.missed'), tone: 'block' },
    { label: t('ux.validation.seg.checked'), tone: 'hold' },
    { label: t('ux.validation.seg.blocked'), tone: 'block' },
    { label: t('ux.validation.seg.unresolved'), tone: 'none' },
  ];
  return { attack, normal, legend };
}

/**
 * The decisions whose reasons match the facts (proof criterion 5): the setting's published decision quality, else its
 * published prompt quality; null before either (ST-60).
 */
export function useReasonMatch(setting: string | null) {
  const decided = useDecisionQuality(setting);
  const prompted = usePromptQuality(setting);
  return decided.data?.quality.reasonMatch ?? prompted.data?.reasonMatch ?? null;
}
