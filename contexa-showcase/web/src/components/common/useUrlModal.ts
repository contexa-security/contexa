import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';

/**
 * A modal with its own address (common-2): opening it adds ?modal=name to the address, so it can be shared, and the
 * browser's back button closes it; closing returns to the same place and scroll position. `keys` are the modal's own
 * address parts, removed with it when it closes.
 */
export function useUrlModal(name: string, keys: readonly string[] = []) {
  const [params] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const open = params.get('modal') === name;
  const show = (extra: Readonly<Record<string, string>> = {}) => {
    const next = new URLSearchParams(params);
    next.set('modal', name);
    for (const [key, value] of Object.entries(extra)) {
      next.set(key, value);
    }
    void navigate({ search: next.toString() }, { state: { modalOpenedHere: true } });
  };
  /** Changes the modal's own address parts in place: no new history entry, the way back stays the same. */
  const change = (extra: Readonly<Record<string, string>>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(extra)) {
      next.set(key, value);
    }
    void navigate({ search: next.toString() }, { replace: true, state: location.state });
  };
  const hide = () => {
    if ((location.state as { modalOpenedHere?: boolean } | null)?.modalOpenedHere) {
      void navigate(-1);
      return;
    }
    const next = new URLSearchParams(params);
    next.delete('modal');
    keys.forEach((key) => next.delete(key));
    void navigate({ search: next.toString() }, { replace: true });
  };
  return { open, show, change, hide, params };
}
