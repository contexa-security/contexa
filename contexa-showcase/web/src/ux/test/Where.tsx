import { useLocation } from 'react-router-dom';

/** Where the router is, for a test to read after a navigation. */
export function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}
