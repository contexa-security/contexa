import { Navigate, useParams, useSearchParams } from 'react-router-dom';
import { DETAIL_TABS, detailSearch, type DetailTab } from './useDetail';

/**
 * The decision details' own address (/run/:runId/detail?step=&tab=, 7.7) and the old anatomy address
 * (/runs/:runId/steps/:stepNo, D-37): both open the window over the first screen, so a shared link lands on the
 * details and closing them leaves the visitor at the start of the demo.
 */
export function DetailAddress() {
  const { runId = '', stepNo } = useParams();
  const [params] = useSearchParams();
  const step = Math.max(1, Number(stepNo ?? params.get('step') ?? 1) || 1);
  const asked = params.get('tab') ?? '';
  const tab: DetailTab = (DETAIL_TABS as readonly string[]).includes(asked)
    ? (asked as DetailTab)
    : 'summary';
  // The address's other parts (the language, the route) stay with it.
  const rest = new URLSearchParams(params);
  rest.delete('step');
  rest.delete('tab');
  const others = rest.toString();
  return (
    <Navigate
      replace
      to={{ pathname: '/', search: `?${detailSearch(runId, step, tab)}${others ? `&${others}` : ''}` }}
    />
  );
}
