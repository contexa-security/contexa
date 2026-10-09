import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useVisitor } from '../../api/queries';
import { useTeasers } from '../../api/teasers';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import experience from '../../pages/try/Experience.module.css';
import { AppHeader } from '../AppHeader';
import { TermScope } from '../common/Glossary';
import { routeFlow } from './flow';
import { JourneyBar } from './JourneyParts';
import { ActionBar, MoreRow, StepHeader } from './StepParts';

interface RouteScreenProps {
  readonly title: ReactNode;
  readonly purpose: ReactNode;
  /** The screen's one source tag (U-4). */
  readonly source?: ReactNode;
  /** A role change announced before the head (e2-scene, D-36). */
  readonly banner?: ReactNode;
  /** The content: what the screen is for, then its notes and conclusion. */
  readonly children: ReactNode;
  /** The chips that open more of that content (folds, originals, details), right under it. */
  readonly more?: ReactNode;
  /** The "just seen" band of the screen, if it is one of the eight places. */
  readonly justSaw?: ReactNode;
  /** The main button's own words where the route's "next · {step}" is not the copy source's. */
  readonly nextLabel?: string;
  /** The screen those words lead to, when the routes lead on differently; elsewhere the band's step name is used. */
  readonly nextLabelFor?: string;
  /** A main action in place of the route's next button (a send button). */
  readonly main?: ReactNode;
  /** Other ways on from the screen, on the left of the action area where "back" would be (the introduction's paths). */
  readonly start?: ReactNode;
  /** Whether the action area offers "skip"; the introduction offers its own ways instead. */
  readonly skip?: boolean;
}

/**
 * Every screen of a route in the one order and the one set of places (U-9): the place band, a role change, the head
 * (headline, purpose, source), the content, the "more" row, the "just seen" band, and the action area with the way
 * back, skip and the one main button under the teaser band. A screen supplies only what is its own; the frame keeps
 * the order, so no screen can place them differently.
 */
export function RouteScreen({
  title,
  purpose,
  source = null,
  banner = null,
  children,
  more = null,
  justSaw = null,
  nextLabel,
  nextLabelFor,
  main,
  start = null,
  skip = true,
}: RouteScreenProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  useVisitor();
  const position = useJourneyPosition();
  const teasers = useTeasers();
  const flow = routeFlow(t, language, position, teasers.data, nextLabel, nextLabelFor);
  return (
    <>
      <AppHeader />
      <main id="main" className={experience.page}>
        <JourneyBar />
        <TermScope>
          <div className={experience.step}>
            {banner}
            <StepHeader title={title} purpose={purpose} source={source} />
            {children}
            {more ? <MoreRow>{more}</MoreRow> : null}
            {justSaw}
            <ActionBar
              back={flow.back}
              start={start}
              main={main ?? flow.next}
              teaser={main ? null : flow.teaser}
              skip={skip}
            />
          </div>
        </TermScope>
      </main>
    </>
  );
}
