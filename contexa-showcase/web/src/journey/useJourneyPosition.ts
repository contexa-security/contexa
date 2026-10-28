import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useJourneyUpdate } from '../api/journey';
import { useVisitor } from '../api/queries';
import { nextScreen, previousScreen, type Difference } from './journey';
import { rememberTrack } from './trackMemory';
import { useJourneyPlace } from './useJourneyPlace';

/**
 * Where the visitor is, kept on the server (work 14): the screen reports its place when it opens, so a reload or
 * another tab returns to the same place, and the differences seen are the server's. The route comes from the address
 * (?route=intro, D-37) or else from the stored journey.
 */
export function useJourneyPosition() {
  const location = useLocation();
  const visitor = useVisitor();
  const update = useJourneyUpdate();
  const place = useJourneyPlace();
  const { route, screen } = place;
  const screenId = screen?.id ?? null;
  const act = screen?.act ?? null;
  const track = screen?.track ?? null;

  // The screens both tracks share lead back to the next-chooser of the track the visitor came from.
  useEffect(() => {
    if (track === 'A' || track === 'H') {
      rememberTrack(track);
    }
  }, [track]);

  useEffect(() => {
    // Only the main flow is a place to return to; a "learn more" screen (group 0) leaves the stored place as it is, so
    // "back to the flow" leads to the screen the visitor left the flow from.
    if (!visitor.isSuccess || screenId === null || act === 0) {
      return;
    }
    void update({ route, step: screenId, ...(act === null ? {} : { act }) });
    // The update function is recreated on every render; the place is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visitor.isSuccess, route, screenId, act]);

  return {
    route,
    screen,
    differences: place.differences,
    next: nextScreen(route, location.pathname),
    previous: previousScreen(route, location.pathname),
    /** Marks a difference as seen where the screen shows it (thread: six places fill the badge). */
    see: (difference: Difference) => update({ difference }),
  };
}
