import { useLocation, useSearchParams } from 'react-router-dom';
import { useJourney } from '../api/journey';
import { useVisitor } from '../api/queries';
import { routeAt, screenAt, skipTarget, type Route } from './journey';

/**
 * Where the visitor is, read only: the route (`routeAt`: the address's ?route=, a screen of one route only, else the
 * stored journey; D-33, D-37), the screen at this address, the differences seen and where "skip" leads. The place band and the action area read it, so every screen
 * shows the same place and the same skip without passing them down.
 */
export function useJourneyPlace() {
  const location = useLocation();
  const [params] = useSearchParams();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const stored = journey.data?.state.route ?? 'DEFAULT';
  const route: Route = routeAt(location.pathname, params.get('route'), stored);
  return {
    route,
    screen: screenAt(route, location.pathname),
    differences: journey.data?.state.differences ?? [],
    skip: skipTarget(route, location.pathname),
  };
}
