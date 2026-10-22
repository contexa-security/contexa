import type { useTranslation } from 'react-i18next';
import { useBenchmark, useDecisionQuality, type BenchmarkCase } from '../../api/benchmark';
import { usePromptQuality } from '../../api/promptQuality';
import { StateScreen } from '../../components/StateScreen';
import { useBenchSetting } from './benchPlace';

type Translate = ReturnType<typeof useTranslation>['t'];

/** The benchmark of the chosen setting, or the state to show in its place. */
export function useBenchView() {
  const { setting } = useBenchSetting();
  const benchmark = useBenchmark(setting);
  const view = benchmark.data ?? null;
  const state = benchmark.isPending ? (
    <StateScreen kind="loading" />
  ) : benchmark.isError ? (
    <StateScreen kind="error" onRetry={() => void benchmark.refetch()} />
  ) : null;
  return { view: view?.spec ? view : null, empty: view !== null && !view.spec, state };
}

/** A method's name as the benchmark writes it; the approval and owner check carries the mark of its footnote. */
export function controlName(t: Translate, control: string): string {
  return `${t(`control.${control}.name`)}${control === 'C2' ? ' *' : ''}`;
}

/**
 * A situation's name in the plain words of the redesign (화면재편-기획안 11절): the dictionary's name for the case key,
 * the server's own title for a case the dictionary does not know yet.
 */
export function caseName(t: Translate, row: Pick<BenchmarkCase, 'key' | 'title'>, language: string): string {
  return t(`bench.r7.caseName.${row.key}`, { defaultValue: row.title[language] ?? row.key });
}

/**
 * G5 of the v21 plan as the benchmark states it: the decisions whose reason codes all cite lines that state them, from
 * the setting's published decision quality (BM-S8), else from its published prompt quality; null before either.
 */
export function useReasonMatch(
  setting: string | null,
): { readonly hits: number; readonly total: number } | null {
  const decided = useDecisionQuality(setting);
  const prompted = usePromptQuality(setting);
  return decided.data?.quality.reasonMatch ?? prompted.data?.reasonMatch ?? null;
}
