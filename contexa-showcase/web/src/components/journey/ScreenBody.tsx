import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import experience from '../../pages/try/Experience.module.css';
import { routeFlow } from './flow';
import { ActionBar, MoreRow, StepHeader } from './StepParts';

export interface ScreenBodyProps {
  readonly title: ReactNode;
  /** What the visitor does here, in one line (R-5). */
  readonly purpose: ReactNode;
  /** The screen's source, until the part's redo moves it to the source line (R-10). */
  readonly source?: ReactNode;
  /** The one thing the screen is for (R-1). */
  readonly children: ReactNode;
  /** The one "see details" chip under the body, on result and reason screens only (R-2). */
  readonly more?: ReactNode;
  /** The source line under the body (R-10): one line for the whole screen. */
  readonly sourceLine?: ReactNode;
  /** The way back when the screen's own flow differs from the route's (a try in its async mode). */
  readonly back?: { readonly to: string; readonly label: string } | null;
  /** The screen's own main action in place of the flow's next button (Send, the end's paths). */
  readonly main?: ReactNode;
  /**
   * Left over from the old frame (role band, "just seen" band, button words, other ways in, skip): not drawn. The
   * screens still passing them are cleaned up as their part is redone (R3-R6).
   */
  readonly banner?: ReactNode;
  readonly justSaw?: ReactNode;
  readonly nextLabel?: string;
  readonly nextLabelFor?: string;
  readonly start?: ReactNode;
  readonly skip?: boolean;
}

/**
 * The inside of every screen of the main flow (화면재편-기획안 5절, R-3): the title zone, the body, the source line and
 * the action bar, in that order. The page around it (top bar, main) is RouteScreen's or a try's own. "Skip this part"
 * belongs to a part's briefing (T0, 15절), which draws its own frame (BriefingPage); nowhere else.
 */
export function ScreenBody({
  title,
  purpose,
  source = null,
  children,
  more = null,
  sourceLine = null,
  back,
  main,
}: ScreenBodyProps) {
  const { t } = useTranslation();
  const position = useJourneyPosition();
  const flow = routeFlow(t, position);
  return (
    <div className={experience.step}>
      <StepHeader title={title} purpose={purpose} source={source} />
      <div className={experience.body} data-zone="body">
        {children}
        {more ? <MoreRow>{more}</MoreRow> : null}
      </div>
      {sourceLine ? (
        <p className={experience.sourceLine} data-zone="source">
          {sourceLine}
        </p>
      ) : null}
      <ActionBar
        back={back === undefined ? flow.back : back}
        main={main === undefined ? flow.next : main}
      />
    </div>
  );
}
