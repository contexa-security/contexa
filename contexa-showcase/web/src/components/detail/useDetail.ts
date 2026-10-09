import { useUrlModal } from '../common/useUrlModal';

/** The decision details' six tabs, in the design's order (anat-1). */
export const DETAIL_TABS = ['summary', 'received', 'process', 'prompt', 'answer', 'original'] as const;
export type DetailTab = (typeof DETAIL_TABS)[number];

export const DETAIL_MODAL = 'detail';
/** The window's own address parts; named apart from the screens' own (the lab result's run, the rules' tab). */
export const DETAIL_KEYS = { run: 'detailRun', step: 'detailStep', tab: 'detailTab' } as const;

/**
 * The decision details' address (7.7, common-2): opened over the screen it is opened from as
 * ?modal=detail&detailRun=&detailStep=&detailTab=, so closing or the back button returns to that screen and its scroll
 * position, and the address can be shared. Changing the tab or the request replaces the address; it adds no history.
 */
export function useDetail() {
  const modal = useUrlModal(DETAIL_MODAL, Object.values(DETAIL_KEYS));
  const runId = modal.params.get(DETAIL_KEYS.run);
  const tabParam = modal.params.get(DETAIL_KEYS.tab);
  const tab: DetailTab = (DETAIL_TABS as readonly string[]).includes(tabParam ?? '')
    ? (tabParam as DetailTab)
    : 'summary';
  const step = Math.max(1, Number(modal.params.get(DETAIL_KEYS.step) ?? 1) || 1);
  const open = modal.open && runId !== null;
  return {
    open,
    runId: open ? runId : null,
    step,
    tab,
    show: (run: string, stepNo = 1, start: DetailTab = 'summary') =>
      modal.show({ [DETAIL_KEYS.run]: run, [DETAIL_KEYS.step]: String(stepNo), [DETAIL_KEYS.tab]: start }),
    setTab: (next: DetailTab) => modal.change({ [DETAIL_KEYS.tab]: next }),
    setStep: (next: number) =>
      modal.change({ [DETAIL_KEYS.step]: String(next), [DETAIL_KEYS.tab]: 'summary' }),
    hide: modal.hide,
  };
}

/** The address of a run's decision details opened on their own (shared, or an old anatomy address). */
export function detailSearch(runId: string, stepNo = 1, tab: DetailTab = 'summary'): string {
  return new URLSearchParams({
    modal: DETAIL_MODAL,
    [DETAIL_KEYS.run]: runId,
    [DETAIL_KEYS.step]: String(stepNo),
    [DETAIL_KEYS.tab]: tab,
  }).toString();
}
