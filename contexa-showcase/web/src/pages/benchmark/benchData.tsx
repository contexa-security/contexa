import type { useTranslation } from 'react-i18next';
import { useBenchmark } from '../../api/benchmark';
import { StateScreen } from '../../components/StateScreen';
import { useBenchSetting } from './benchPlace';

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

/** An approach's name as the benchmark writes it; the business-record rule carries the mark of its footnote. */
export function controlName(t: ReturnType<typeof useTranslation>['t'], control: string): string {
  return `${t(`control.${control}.name`)}${control === 'C2' ? ' *' : ''}`;
}
