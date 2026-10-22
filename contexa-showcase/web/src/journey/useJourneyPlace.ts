import { useLocation } from 'react-router-dom';
import { useJourney } from '../api/journey';
import { useVisitor } from '../api/queries';
import { MORE_PATH, screenAt, skipTarget, type Route } from './journey';

/** The address of the timing topic's resend screen, the screen a run sent "from=timing" belongs to. */
const TIMING_RESEND = '/try/timing/try';

/**
 * Where the visitor is, read only: the screen at this address on the main flow or in a "learn more" topic, the
 * differences seen and where "skip" leads from a cover. The top bar and the frame read it, so every screen shows the
 * same place.
 */
export function useJourneyPlace() {
  const location = useLocation();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const route: Route = 'DEFAULT';
  // 4-1 sends its request on the try's run step (/try/attacker/run?from=timing...); that run belongs to 4-1.
  const fromTiming = new URLSearchParams(location.search).get('from')?.startsWith('timing') === true;
  const path = fromTiming && location.pathname.endsWith('/run') ? TIMING_RESEND : location.pathname;
  return {
    route,
    screen: screenAt(route, path),
    differences: journey.data?.state.differences ?? [],
    skip: skipTarget(route, location.pathname),
    /** The hub of "learn more", which is no screen of a topic but shows the same way back to the flow. */
    more: location.pathname === MORE_PATH,
  };
}
