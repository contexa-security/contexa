import type { TFunction } from 'i18next';
import type { ReactNode } from 'react';
import type { TeasersView } from '../../api/teasers';
import { teaserCopy } from '../../journey/copy';
import type { Route, Screen } from '../../journey/journey';
import { TeaserBand } from './Cards';
import { NextLink } from './StepParts';

/**
 * How a screen connects to its neighbours (U-3): the way back to the screen before on the route, the main button, and
 * the teaser band the route puts over it.
 */
export interface RouteFlow {
  readonly back: { readonly to: string; readonly label: string } | null;
  readonly next: ReactNode;
  /** The teaser band over the main button (0-3 table); null where the route puts a plain "next" button. */
  readonly teaser: ReactNode;
}

/**
 * A neighbouring screen's name on a button: the step name the place band shows, with its act in front when the screen
 * belongs to another act ("back · act 1 wrap-up"), so a button never names a step the band does not show.
 */
export function stepName(t: TFunction, target: Screen, from: Screen | null): string {
  const name = t(`place.step.${target.id}`);
  return target.act !== null && from?.act !== null && from?.act !== undefined && target.act !== from.act
    ? `${t('act.label', { n: target.act })} ${name}`
    : name;
}

interface Place {
  readonly route: Route;
  readonly screen: Screen | null;
  readonly next: Screen | null;
  readonly previous: Screen | null;
  readonly differences: readonly number[];
}

/**
 * The flow of a screen from its place on the route, the same for every screen: back names the screen before, the main
 * button names the next one (or reads "see next" under a teaser band), and on the concept path both keep ?route=intro
 * (D-37). A screen whose main button names its next step in its own words passes that label, and names the screen the
 * words are for when the routes lead on differently: on a route where the next screen is another one, the band's step
 * name is used (U-11, S12).
 */
export function routeFlow(
  t: TFunction,
  language: 'ko' | 'en',
  place: Place,
  teasers: TeasersView | undefined,
  nextLabel?: string,
  nextLabelFor?: string,
): RouteFlow {
  const intro = place.route === 'INTRO';
  const suffix = intro ? '?route=intro' : '';
  const { screen, next, previous } = place;
  const teaser =
    !intro && screen?.teaser && !screen.actEnd && next ? (
      <TeaserBand copy={teaserCopy(t, language, screen.teaser, teasers, place.differences.length)} />
    ) : null;
  return {
    back: previous
      ? { to: `${previous.path}${suffix}`, label: t('step.back', { step: stepName(t, previous, screen) }) }
      : null,
    next: next ? (
      <NextLink
        to={`${next.path}${suffix}`}
        label={
          teaser
            ? t('teaser.see')
            : nextLabel && (!nextLabelFor || next.id === nextLabelFor)
              ? nextLabel
              : t('step.next', { step: stepName(t, next, screen) })
        }
      />
    ) : null,
    teaser,
  };
}
