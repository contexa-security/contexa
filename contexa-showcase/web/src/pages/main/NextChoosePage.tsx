import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useAgentCaseKeys } from '../../api/agentCase';
import { useJourney } from '../../api/journey';
import { useVisitor } from '../../api/queries';
import { ChoiceCards, type Choice } from '../../components/main/ChoiceCards';
import { ChooseScreen } from '../../components/main/ChooseScreen';
import { MainLink } from '../../components/main/MainScreen';
import { entryOf, otherTrack, type Track } from '../../journey/journey';
import { AGENT_PATHS } from './agentGroup';
import { ROLE_PATHS } from './mainCases';
import { pastLine, type RecapLane } from './recap';

type Own = Exclude<Track, 'C'>;

/** The case the visitor finished, from the address the lane's end leads to (lanes.json). */
type From = 'attack' | 'normal' | 'insider';

/** Where the suggested opposite scene leads from each lane: the other side of the pair. */
const OPPOSITE: Readonly<Record<From | 'agent', string>> = {
  attack: ROLE_PATHS.owner.request,
  normal: ROLE_PATHS.attacker.request,
  insider: ROLE_PATHS.attacker.request,
  agent: `${AGENT_PATHS.request}?case=N1`,
};

function fromOf(value: string | null): From {
  return value === 'normal' || value === 'insider' ? value : 'attack';
}

/**
 * H-6 and A-6, what to see next (구현계획 NW-4): one line of what the visitor just saw (the covers' "지난 주제에서 확인한
 * 것", from the visitor's own run), four cards with the opposite scene first and suggested, so the pair of the demo,
 * the attack stopped and the real work let through, is one choice away, and the wrap-up as the one main button. Only the
 * suggested card tells more under its title: with the line above, the screen stays within 120 characters (AC-N1).
 */
export function NextChoose({ track }: { readonly track: Own }) {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const screenNumber = track === 'A' ? 'A-6' : 'H-6';
  const lane: RecapLane = track === 'A' ? 'agent' : fromOf(params.get('from'));
  const agentCases = useAgentCaseKeys();
  const recap = pastLine(lane, journey.data?.runs, agentCases);
  const words = {
    ...(recap.n === undefined ? {} : { n: recap.n }),
    ...Object.fromEntries(Object.entries(recap.parts ?? {}).map(([place, key]) => [place, t(key)])),
  };
  const other = otherTrack(track);
  const cards: readonly Choice[] = [
    {
      id: 'opposite',
      title: t(`next.opposite.${lane}.title`),
      sub: t(`next.opposite.${lane}.sub`),
      to: OPPOSITE[lane],
      icon: 'refresh',
      recommended: true,
    },
    {
      id: 'change',
      title: t('next.change.title'),
      to: track === 'A' ? '/lab/agent' : '/compare/change',
      icon: 'chart',
    },
    {
      id: 'deeper',
      title: t('next.deeper.title'),
      to: `/deeper?track=${track}`,
      icon: 'search',
    },
    {
      id: 'other',
      title: t(`next.other.${other === 'A' ? 'agent' : 'person'}.title`),
      to: entryOf(other),
      icon: other === 'A' ? 'agent' : 'user',
    },
  ];
  return (
    <ChooseScreen
      title={t(`main.${screenNumber}.title`)}
      intro={t(`main.${screenNumber}.intro`)}
      recap={<span key={recap.key}>{t(recap.key, words)}</span>}
      main={<MainLink to="/summary">{t(`main.${screenNumber}.cta`)}</MainLink>}
    >
      <ChoiceCards cards={cards} label={t(`main.${screenNumber}.title`)} badge={t('next.opposite.recommended')} />
    </ChooseScreen>
  );
}
