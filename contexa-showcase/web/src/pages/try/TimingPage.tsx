import type { ComponentType } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import CompareScreen from './timing/CompareScreen';
import ConceptScreen from './timing/ConceptScreen';
import ResendScreen from './timing/ResendScreen';
import WhenScreen from './timing/WhenScreen';

const STEPS = ['concept', 'try', 'compare', 'when'] as const;
type TimingStep = (typeof STEPS)[number];

const SCREENS: Readonly<Record<TimingStep, ComponentType>> = {
  concept: ConceptScreen,
  try: ResendScreen,
  compare: CompareScreen,
  when: WhenScreen,
};

/**
 * Part 4, when to stop it (화면재편-기획안 7절 4-0 to 4-3), one screen per address (/try/timing/:step): the cover with
 * the same export in time order both ways, sending the attack "from the next request" next to the one sent before
 * the response, the measured two by two, and the two questions that choose the way. The wrap-up (4-4) is
 * TimingEndPage. Every time and count on these screens is a stored run or the server's count of the measurement.
 */
export default function TimingPage() {
  const { step = 'concept' } = useParams();
  if (!(STEPS as readonly string[]).includes(step)) {
    return <Navigate to="/try/timing/concept" replace />;
  }
  const Screen = SCREENS[step as TimingStep];
  return <Screen />;
}
