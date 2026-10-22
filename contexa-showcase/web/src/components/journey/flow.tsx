import type { TFunction } from 'i18next';
import type { ReactNode } from 'react';
import { MORE_PATH, type Screen } from '../../journey/journey';
import { NextLink } from './StepParts';

/** How a screen connects to its neighbours: the way back and the one main button. */
export interface RouteFlow {
  readonly back: { readonly to: string; readonly label: string } | null;
  readonly next: ReactNode;
  /** Kept for the screens not yet redone; the teaser band is gone (R-6), so it is always null. */
  readonly teaser: ReactNode;
}

interface Place {
  readonly screen: Screen | null;
  readonly next: Screen | null;
  readonly previous: Screen | null;
}

/**
 * The flow of a "learn more" screen from its place in its topic (최종화면-구현계획 2절): "back" leads to the screen
 * before in the topic, the main button names the next screen of the topic, and the topic's last screen leads back to
 * the hub. A screen with its own action (Send) passes its own main.
 */
export function routeFlow(t: TFunction, place: Place): RouteFlow {
  const { screen, next, previous } = place;
  let main: ReactNode = null;
  if (screen && next) {
    main = <NextLink to={next.path} label={t('frame.nextNamed', { name: t(`more.name.${next.id}`) })} />;
  } else if (screen && screen.act === 0) {
    main = <NextLink to={MORE_PATH} label={t('more.toHub')} />;
  }
  return {
    back: previous ? { to: previous.path, label: t('frame.back') } : null,
    next: main,
    teaser: null,
  };
}
