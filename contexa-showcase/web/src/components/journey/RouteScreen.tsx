import { useVisitor } from '../../api/queries';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import experience from '../../pages/try/Experience.module.css';
import { AppHeader } from '../AppHeader';
import { TermScope } from '../common/Glossary';
import { ScreenBody, type ScreenBodyProps } from './ScreenBody';

/**
 * A screen of the main flow in the redesigned frame (화면재편-기획안 5절, R-3): the top bar, then the inside every screen
 * shares (ScreenBody: title zone, body, source line, action bar). The page carries the screen's type (T1-T8), which
 * the automatic check (e2e/frame-audit.mjs) reads.
 */
export function RouteScreen(props: ScreenBodyProps) {
  useVisitor();
  const position = useJourneyPosition();
  return (
    <>
      <AppHeader />
      <main id="main" className={experience.page} data-type={position.screen?.type}>
        <TermScope>
          <ScreenBody {...props} />
        </TermScope>
      </main>
    </>
  );
}
